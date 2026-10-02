from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import random
import threading
import time
from concurrent.futures import FIRST_EXCEPTION, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import IO, Any, Callable, Dict, Iterator, List, Mapping, Optional, Sequence, Union
from urllib.parse import quote, urlencode, urlsplit

import urllib3

from .errors import IntegrityError, NotFoundError, NotModifiedError, ObjectStorageError

__all__ = ["Client", "Bucket", "MultipartUpload"]

VERSION = "1.0.0"
MiB = 1 << 20
MIN_PART_SIZE = 5 * MiB
MAX_PARTS = 10000

Body = Union[bytes, bytearray, memoryview, str]


def _parse_time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        if value.endswith("Z") or "T" in value:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsedate_to_datetime(value)
    except (ValueError, TypeError):
        return None


@dataclass
class PublicRule:
    """Makes the objects under ``prefix`` ("" is the whole bucket) readable by
    anyone without a key; ``list`` also lets anyone list those keys."""

    prefix: str = ""
    list: bool = False

    @classmethod
    def _from(cls, d: Mapping[str, Any]) -> "PublicRule":
        return cls(d.get("prefix", "") or "", bool(d.get("list", False)))


@dataclass
class BucketInfo:
    name: str
    region: str = ""
    created_at: Optional[datetime] = None
    # What anyone may read; get_bucket fills it, list_buckets does not.
    public: List[PublicRule] = field(default_factory=list)

    @classmethod
    def _from(cls, d: Mapping[str, Any]) -> "BucketInfo":
        return cls(d.get("name", ""), d.get("region", ""), _parse_time(d.get("createdAt")), [PublicRule._from(r) for r in d.get("public") or []])


@dataclass
class ObjectInfo:
    key: str
    size: int = 0
    etag: str = ""
    last_modified: Optional[datetime] = None
    content_type: str = ""
    metadata: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def _from(cls, d: Mapping[str, Any]) -> "ObjectInfo":
        return cls(
            key=d.get("key", ""),
            size=int(d.get("size", 0)),
            etag=str(d.get("etag", "")).strip('"'),
            last_modified=_parse_time(d.get("lastModified")),
            content_type=d.get("contentType", "") or "",
            metadata=dict(d.get("metadata") or {}),
        )

    @classmethod
    def _from_headers(cls, key: str, headers: Mapping[str, str]) -> "ObjectInfo":
        size = 0
        cr = headers.get("Content-Range")
        if cr and "/" in cr:
            size = int(cr.rsplit("/", 1)[1])
        elif headers.get("Content-Length"):
            size = int(headers["Content-Length"])
        meta = {k[7:].lower(): v for k, v in headers.items() if k.lower().startswith("x-meta-")}
        return cls(
            key=key,
            size=size,
            etag=(headers.get("ETag") or "").strip('"'),
            last_modified=_parse_time(headers.get("Last-Modified")),
            content_type=headers.get("Content-Type", ""),
            metadata=meta,
        )


@dataclass
class ListPage:
    objects: List[ObjectInfo]
    folders: List[str]
    next_cursor: Optional[str]


@dataclass
class Part:
    number: int
    etag: str
    size: int = 0


@dataclass
class Link:
    url: str
    method: str
    expires_at: Optional[datetime]


def _escape_key(key: str) -> str:
    return "/".join(quote(seg, safe="") for seg in key.split("/"))


def _md5(data: Body) -> str:
    return hashlib.md5(data).hexdigest()  # noqa: S324 - integrity, not security


def _check_etag(etag: str, digest: str, what: str) -> None:
    etag = etag.strip('"')
    if len(etag) == 32 and "-" not in etag and etag != digest:
        raise IntegrityError(f"{what}: the stored data does not match what was sent (ETag {etag}, MD5 {digest})")


def _guess_type(name: str) -> str:
    return mimetypes.guess_type(name)[0] or "application/octet-stream"


class ObjectStream:
    """A download in progress. Iterate with ``iter_chunks()``, ``read()`` it,
    or use it as a context manager; close it when done."""

    def __init__(self, response: urllib3.BaseHTTPResponse, info: ObjectInfo) -> None:
        self._resp = response
        self.info = info
        self.content_range = response.headers.get("Content-Range")

    def read(self, amt: Optional[int] = None) -> bytes:
        return self._resp.read(amt)

    def iter_chunks(self, chunk_size: int = 1 * MiB) -> Iterator[bytes]:
        yield from self._resp.stream(chunk_size)

    def close(self) -> None:
        self._resp.release_conn()

    def __enter__(self) -> "ObjectStream":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


_RETRY_STATUSES = {429, 500, 502, 503, 504}


class Client:
    """A client of one region's Object Storage endpoint. Thread-safe."""

    def __init__(
        self,
        endpoint: str,
        access_key_id: str = "",
        secret_access_key: str = "",
        *,
        part_size: int = 16 * MiB,
        multipart_threshold: Optional[int] = None,
        concurrency: int = 8,
        max_retries: int = 4,
        connect_timeout: float = 10.0,
        read_timeout: float = 120.0,
        pool_maxsize: Optional[int] = None,
        user_agent: str = "",
    ) -> None:
        # Without a key the client is anonymous: it reads (and, where allowed,
        # lists) only what buckets made public.
        if not endpoint or bool(access_key_id) != bool(secret_access_key):
            raise ValueError("endpoint is required, and access_key_id and secret_access_key together")
        u = urlsplit(endpoint.rstrip("/"))
        if u.scheme not in ("http", "https") or not u.netloc:
            raise ValueError(f"invalid endpoint {endpoint!r}")
        path = u.path[:-3] if u.path.endswith("/v1") else u.path
        self._origin = f"{u.scheme}://{u.netloc}{path}"
        self._base = self._origin + "/v1"
        self._auth = f"Bearer {access_key_id}:{secret_access_key}" if access_key_id else ""
        self.part_size = max(part_size, MIN_PART_SIZE)
        self.multipart_threshold = multipart_threshold or 2 * self.part_size
        self.concurrency = max(1, concurrency)
        self.max_retries = max(0, max_retries)
        self._ua = f"thailandhosting-object-storage-sdk-python/{VERSION}" + (f" {user_agent}" if user_agent else "")
        self._http = urllib3.PoolManager(
            maxsize=pool_maxsize or self.concurrency * 2,
            block=False,
            retries=False,
            timeout=urllib3.Timeout(connect=connect_timeout, read=read_timeout),
        )

    # ---- plumbing ----

    def _request(
        self,
        method: str,
        path: str,
        *,
        query: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        body: Optional[Body] = None,
        stream: bool = False,
        retry_post: bool = False,
        expect: Sequence[int] = (),
    ) -> urllib3.BaseHTTPResponse:
        url = self._base + path
        if query:
            url += "?" + urlencode({k: v for k, v in query.items() if v not in (None, "")})
        h = {"User-Agent": self._ua}
        if self._auth:
            h["Authorization"] = self._auth
        if headers:
            h.update(headers)
        attempt = 0
        while True:
            try:
                resp = self._http.request(method, url, body=body, headers=h, preload_content=not stream, redirect=False)
            except urllib3.exceptions.HTTPError:
                # The request may have reached the service; only a repeatable
                # one is sent again.
                if attempt < self.max_retries and (method != "POST" or retry_post):
                    self._sleep(attempt)
                    attempt += 1
                    continue
                raise
            status = resp.status
            if (expect and status in expect) or (not expect and 200 <= status < 300):
                return resp
            err = self._error(resp)
            retryable = status in _RETRY_STATUSES and (method != "POST" or (retry_post and status in (429, 503)))
            if retryable and attempt < self.max_retries:
                self._sleep(attempt, resp.headers.get("Retry-After"))
                attempt += 1
                continue
            raise err

    @staticmethod
    def _sleep(attempt: int, retry_after: Optional[str] = None) -> None:
        d = min(0.2 * (2 ** min(attempt, 6)), 10.0)
        d = d / 2 + random.uniform(0, d / 2)
        if retry_after:
            try:
                d = max(d, min(float(retry_after), 30.0))
            except ValueError:
                pass
        time.sleep(d)

    @staticmethod
    def _error(resp: urllib3.BaseHTTPResponse) -> ObjectStorageError:
        data = resp.data if resp.data is not None else b""
        resp.release_conn()
        code = resp.headers.get("X-Error-Code") or ""
        message = resp.reason or ""
        try:
            doc = json.loads(data or b"{}").get("error") or {}
            code, message = doc.get("code") or code, doc.get("message") or message
        except (ValueError, AttributeError):
            pass
        code = code or (resp.reason or "error").lower().replace(" ", "_")
        cls = NotFoundError if resp.status == 404 else ObjectStorageError
        return cls(resp.status, code, message)

    def _json(self, method: str, path: str, payload: Any = None, *, query: Optional[Mapping[str, Any]] = None, retry_post: bool = False) -> Any:
        body = None
        headers = None
        if payload is not None:
            body = json.dumps(payload).encode()
            headers = {"Content-Type": "application/json"}
        resp = self._request(method, path, query=query, headers=headers, body=body, retry_post=retry_post)
        if not resp.data:
            return None
        return json.loads(resp.data)

    # ---- buckets ----

    def list_buckets(self) -> List[BucketInfo]:
        """The buckets this access key can use."""
        return [BucketInfo._from(b) for b in self._json("GET", "/buckets")["buckets"]]

    def create_bucket(self, name: str) -> BucketInfo:
        """Create a bucket (3-63 characters of a-z, 0-9, dots and hyphens)."""
        return BucketInfo._from(self._json("PUT", "/buckets/" + quote(name, safe="")) or {"name": name})

    def get_bucket(self, name: str) -> BucketInfo:
        return BucketInfo._from(self._json("GET", "/buckets/" + quote(name, safe="")))

    def delete_bucket(self, name: str) -> None:
        """Delete an empty bucket."""
        self._json("DELETE", "/buckets/" + quote(name, safe=""))

    def bucket(self, name: str) -> "Bucket":
        """A handle for one bucket's objects (no request is made)."""
        return Bucket(self, name)

    def close(self) -> None:
        self._http.clear()

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def _part_size_for(self, size: int) -> int:
        ps = self.part_size
        if size > 0 and -(-size // ps) > MAX_PARTS:
            ps = -(-size // MAX_PARTS)
            ps = -(-ps // MiB) * MiB
        return ps


def _put_headers(
    content_type: Optional[str],
    metadata: Optional[Mapping[str, str]],
    cache_control: Optional[str],
    content_disposition: Optional[str],
    content_encoding: Optional[str],
    if_not_exists: bool,
) -> Dict[str, str]:
    h: Dict[str, str] = {}
    if content_type:
        h["Content-Type"] = content_type
    if cache_control:
        h["Cache-Control"] = cache_control
    if content_disposition:
        h["Content-Disposition"] = content_disposition
    if content_encoding:
        h["Content-Encoding"] = content_encoding
    for k, v in (metadata or {}).items():
        h["X-Meta-" + k] = v
    if if_not_exists:
        h["If-None-Match"] = "*"
    return h


def _run_parallel(workers: int, count: int, fn: Callable[[int], Any]) -> List[Any]:
    """Runs fn(0..count-1) on a thread pool, at most `workers` at once;
    the first failure cancels what has not started and is raised."""
    results: List[Any] = [None] * count
    if count == 0:
        return results
    with ThreadPoolExecutor(max_workers=min(workers, count)) as pool:
        futures: Dict[Future, int] = {pool.submit(fn, i): i for i in range(count)}
        done, pending = wait(futures, return_when=FIRST_EXCEPTION)
        for f in pending:
            f.cancel()
        for f in done:
            if f.exception() is not None:
                raise f.exception()  # type: ignore[misc]
        for f, i in futures.items():
            results[i] = f.result()
    return results


class Bucket:
    """The objects of one bucket. Thread-safe."""

    def __init__(self, client: Client, name: str) -> None:
        self._c = client
        self.name = name
        self._path = "/buckets/" + quote(name, safe="")

    def _obj(self, key: str) -> str:
        return self._path + "/objects/" + _escape_key(key)

    # ---- small objects ----

    def put(
        self,
        key: str,
        data: Body,
        *,
        content_type: Optional[str] = None,
        metadata: Optional[Mapping[str, str]] = None,
        cache_control: Optional[str] = None,
        content_disposition: Optional[str] = None,
        content_encoding: Optional[str] = None,
        if_not_exists: bool = False,
    ) -> ObjectInfo:
        """Upload ``data`` (bytes or str) in one request. Use ``upload_file``
        or ``upload_fileobj`` for large or streamed data."""
        if isinstance(data, str):
            data = data.encode()
        headers = _put_headers(content_type or _guess_type(key), metadata, cache_control, content_disposition, content_encoding, if_not_exists)
        resp = self._c._request("PUT", self._obj(key), headers=headers, body=bytes(data))
        info = ObjectInfo._from(json.loads(resp.data))
        _check_etag(info.etag, _md5(data), key)
        return info

    def get(
        self,
        key: str,
        *,
        offset: int = 0,
        length: Optional[int] = None,
        if_none_match: Optional[str] = None,
        if_match: Optional[str] = None,
    ) -> ObjectStream:
        """Stream an object (or ``length`` bytes from ``offset``). Close the
        stream, or use ``with``. ``info.size`` is the whole object's size."""
        headers: Dict[str, str] = {}
        if offset or length:
            headers["Range"] = f"bytes={offset}-{offset + length - 1}" if length else f"bytes={offset}-"
        if if_none_match:
            headers["If-None-Match"] = '"' + if_none_match.strip('"') + '"'
        if if_match:
            headers["If-Match"] = '"' + if_match.strip('"') + '"'
        resp = self._c._request("GET", self._obj(key), headers=headers, stream=True, expect=(200, 206, 304))
        if resp.status == 304:
            resp.release_conn()
            raise NotModifiedError(key)
        return ObjectStream(resp, ObjectInfo._from_headers(key, resp.headers))

    def get_bytes(self, key: str) -> bytes:
        """Download a whole object into memory."""
        resp = self._c._request("GET", self._obj(key))
        return resp.data

    def head(self, key: str) -> ObjectInfo:
        resp = self._c._request("HEAD", self._obj(key))
        return ObjectInfo._from_headers(key, resp.headers)

    def exists(self, key: str) -> bool:
        try:
            self.head(key)
            return True
        except NotFoundError:
            return False

    def delete(self, key: str) -> None:
        """Delete an object; deleting a missing one succeeds."""
        self._c._request("DELETE", self._obj(key))

    def delete_many(self, keys: Sequence[str]) -> None:
        """Delete keys in parallel."""
        _run_parallel(self._c.concurrency, len(keys), lambda i: self.delete(keys[i]))

    def copy(self, src_key: str, dst_key: str, *, source_bucket: Optional[str] = None, metadata: Optional[Mapping[str, str]] = None) -> ObjectInfo:
        """Copy inside the service, without downloading."""
        payload: Dict[str, Any] = {"from": {"bucket": source_bucket or self.name, "key": src_key}, "key": dst_key}
        if metadata is not None:
            payload["metadata"] = dict(metadata)
        return ObjectInfo._from(self._c._json("POST", self._path + "/copy", payload, retry_post=True))

    # ---- listing ----

    def list(self, prefix: str = "", *, delimiter: str = "", cursor: Optional[str] = None, limit: Optional[int] = None) -> ListPage:
        """One page of objects (and folders, with a delimiter)."""
        d = self._c._json("GET", self._path + "/objects", query={"prefix": prefix, "delimiter": delimiter, "cursor": cursor, "limit": limit})
        return ListPage([ObjectInfo._from(o) for o in d.get("objects", [])], list(d.get("folders", [])), d.get("nextCursor"))

    def iter_objects(self, prefix: str = "", *, page_size: Optional[int] = None) -> Iterator[ObjectInfo]:
        """Every object under prefix, fetching pages as it goes."""
        cursor = None
        while True:
            page = self.list(prefix, cursor=cursor, limit=page_size)
            yield from page.objects
            if not page.next_cursor:
                return
            cursor = page.next_cursor

    # ---- links ----

    def create_link(self, key: str, *, expires_in: int = 3600, upload: bool = False) -> Link:
        """A URL that downloads (or, with ``upload=True``, uploads) one object
        without an access key, for ``expires_in`` seconds (at most 7 days)."""
        d = self._c._json("POST", self._path + "/links", {"key": key, "expiresIn": int(expires_in), "method": "PUT" if upload else "GET"}, retry_post=True)
        return Link(d["url"], d.get("method", "GET"), _parse_time(d.get("expiresAt")))

    # ---- public access ----

    def public_access(self) -> List[PublicRule]:
        """What anyone may read in the bucket."""
        d = self._c._json("GET", self._path + "/public")
        return [PublicRule._from(r) for r in d.get("rules") or []]

    def set_public_access(self, rules: Sequence[PublicRule]) -> List[PublicRule]:
        """Replaces what anyone may read: ``[]`` makes the bucket private,
        ``[PublicRule()]`` opens all of it, ``[PublicRule("images/")]`` one
        folder. Needs a key allowed to manage buckets; takes effect within
        about 15 seconds. Returns the rules as stored."""
        payload = {"rules": [{"prefix": r.prefix, "list": r.list} for r in rules]}
        d = self._c._json("PUT", self._path + "/public", payload, retry_post=True)
        return [PublicRule._from(r) for r in d.get("rules") or []]

    def public_url(self, key: str) -> str:
        """The address anyone can open ``key`` at once its folder (or the
        bucket) is public. No request is made."""
        return f"{self._c._origin}/{quote(self.name, safe='')}/{_escape_key(key)}"

    # ---- multipart ----

    def create_multipart_upload(self, key: str, *, content_type: Optional[str] = None, metadata: Optional[Mapping[str, str]] = None) -> "MultipartUpload":
        payload: Dict[str, Any] = {"key": key, "contentType": content_type or _guess_type(key)}
        if metadata:
            payload["metadata"] = dict(metadata)
        d = self._c._json("POST", self._path + "/uploads", payload, retry_post=True)
        return MultipartUpload(self, key, d["uploadId"])

    def resume_multipart_upload(self, key: str, upload_id: str) -> "MultipartUpload":
        return MultipartUpload(self, key, upload_id)

    # ---- large transfers ----

    def upload_file(
        self,
        key: str,
        path: Union[str, "os.PathLike[str]"],
        *,
        content_type: Optional[str] = None,
        metadata: Optional[Mapping[str, str]] = None,
        cache_control: Optional[str] = None,
        content_disposition: Optional[str] = None,
    ) -> ObjectInfo:
        """Upload a local file. Large files go up as parts read from the file
        and sent in parallel; each part is re-read if it must be sent again."""
        path = os.fspath(path)
        size = os.path.getsize(path)
        content_type = content_type or _guess_type(path)
        if size <= self._c.multipart_threshold:
            with open(path, "rb") as f:
                return self.put(key, f.read(), content_type=content_type, metadata=metadata, cache_control=cache_control, content_disposition=content_disposition)
        ps = self._c._part_size_for(size)
        count = -(-size // ps)
        up = self.create_multipart_upload(key, content_type=content_type, metadata=metadata)
        local = threading.local()

        def send(i: int) -> Part:
            # One handle per thread: parallel reads without a shared offset.
            f = getattr(local, "f", None)
            if f is None:
                f = local.f = open(path, "rb")
                handles.append(f)
            f.seek(i * ps)
            return up.upload_part(i + 1, f.read(min(ps, size - i * ps)))

        handles: List[IO[bytes]] = []
        try:
            parts = _run_parallel(self._c.concurrency, count, send)
            return up.complete(parts)
        except BaseException:
            up._abort_quietly()
            raise
        finally:
            for f in handles:
                f.close()

    def upload_fileobj(
        self,
        key: str,
        fileobj: IO[bytes],
        *,
        content_type: Optional[str] = None,
        metadata: Optional[Mapping[str, str]] = None,
    ) -> ObjectInfo:
        """Upload what a binary stream yields (a pipe, a socket, a generated
        export) without knowing its size. Parts are read one after another and
        sent in parallel, holding at most ``concurrency + 1`` in memory."""
        ps = self._c.part_size
        first = _read_full(fileobj, ps)
        if len(first) < ps:
            return self.put(key, first, content_type=content_type, metadata=metadata)
        up = self.create_multipart_upload(key, content_type=content_type, metadata=metadata)
        slots = threading.BoundedSemaphore(self._c.concurrency)
        try:
            with ThreadPoolExecutor(max_workers=self._c.concurrency) as pool:
                futures: List[Future] = []

                def send(n: int, data: bytes) -> Part:
                    try:
                        return up.upload_part(n, data)
                    finally:
                        slots.release()

                n, data = 1, first
                while data:
                    if n > MAX_PARTS:
                        raise ValueError(f"more than {MAX_PARTS} parts of {ps} bytes: use a larger part_size")
                    slots.acquire()
                    if any(f.done() and f.exception() for f in futures):
                        slots.release()
                        break
                    futures.append(pool.submit(send, n, data))
                    n += 1
                    data = _read_full(fileobj, ps)
                parts = [f.result() for f in futures]
            return up.complete(parts)
        except BaseException:
            up._abort_quietly()
            raise

    def download_file(self, key: str, path: Union[str, "os.PathLike[str]"]) -> ObjectInfo:
        """Save an object to ``path``. Large objects come down as parallel
        ranges pinned to the object's ETag. The data is written to
        ``path + '.download'`` and renamed into place."""
        path = os.fspath(path)
        info = self.head(key)
        tmp = path + ".download"
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        try:
            with open(tmp, "wb") as f:
                f.truncate(info.size)
            if info.size <= self._c.multipart_threshold:
                digest = hashlib.md5()  # noqa: S324
                with self.get(key, if_match=info.etag) as s, open(tmp, "r+b") as f:
                    for chunk in s.iter_chunks():
                        f.write(chunk)
                        digest.update(chunk)
                _check_etag(info.etag, digest.hexdigest(), key)
            else:
                ps = self._c.part_size
                count = -(-info.size // ps)
                local = threading.local()
                handles: List[IO[bytes]] = []

                def fetch(i: int) -> None:
                    f = getattr(local, "f", None)
                    if f is None:
                        f = local.f = open(tmp, "r+b")
                        handles.append(f)
                    self._download_range(key, info.etag, f, i * ps, min(ps, info.size - i * ps))

                try:
                    _run_parallel(self._c.concurrency, count, fetch)
                finally:
                    for f in handles:
                        f.close()
            os.replace(tmp, path)
        except BaseException:
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise
        return info

    def _download_range(self, key: str, etag: str, f: IO[bytes], offset: int, length: int) -> None:
        done = 0
        attempt = 0
        while done < length:
            try:
                with self.get(key, offset=offset + done, length=length - done, if_match=etag) as s:
                    f.seek(offset + done)
                    for chunk in s.iter_chunks():
                        f.write(chunk)
                        done += len(chunk)
            except (urllib3.exceptions.HTTPError, ConnectionError):
                if attempt >= self._c.max_retries:
                    raise
            if done < length:
                # The connection broke mid-range: carry on from where it stopped.
                if attempt >= self._c.max_retries:
                    raise IntegrityError(f"{key}: got {done} of {length} bytes at {offset}")
                Client._sleep(attempt)
                attempt += 1


def _read_full(f: IO[bytes], n: int) -> bytes:
    """Reads up to n bytes, looping over short reads (pipes, sockets)."""
    buf = bytearray()
    while len(buf) < n:
        chunk = f.read(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return bytes(buf)


class MultipartUpload:
    """A large upload in progress: send parts (any order, in parallel), then
    ``complete()`` or ``abort()``. ``Bucket.upload_file`` and
    ``upload_fileobj`` do this for you."""

    def __init__(self, bucket: Bucket, key: str, upload_id: str) -> None:
        self.bucket = bucket
        self.key = key
        self.upload_id = upload_id

    def _path(self) -> str:
        return self.bucket._path + "/uploads/" + self.upload_id

    def upload_part(self, number: int, data: Body) -> Part:
        """Send part ``number`` (1-10000); every part but the last must be at
        least 5 MiB. Sending a number again replaces that part."""
        data = bytes(data) if not isinstance(data, bytes) else data
        resp = self.bucket._c._request(
            "PUT", f"{self._path()}/parts/{int(number)}", headers={"Content-Type": "application/octet-stream"}, body=data
        )
        d = json.loads(resp.data)
        _check_etag(d.get("etag", ""), _md5(data), f"part {number}")
        return Part(int(d["number"]), str(d["etag"]).strip('"'), len(data))

    def parts(self) -> List[Part]:
        d = self.bucket._c._json("GET", self._path())
        return [Part(int(p["number"]), str(p["etag"]).strip('"'), int(p.get("size", 0))) for p in d.get("parts", [])]

    def complete(self, parts: Optional[Sequence[Part]] = None) -> ObjectInfo:
        """Join the parts into the object; without ``parts``, every part
        received, in order."""
        payload = None
        if parts is not None:
            payload = {"parts": [{"number": p.number, "etag": p.etag} for p in sorted(parts, key=lambda p: p.number)]}
        try:
            return ObjectInfo._from(self.bucket._c._json("POST", self._path() + "/complete", payload, retry_post=True))
        except NotFoundError:
            # A retry after a completion whose answer was lost.
            return self.bucket.head(self.key)

    def abort(self) -> None:
        try:
            self.bucket._c._json("DELETE", self._path())
        except NotFoundError:
            pass

    def _abort_quietly(self) -> None:
        try:
            self.abort()
        except Exception:  # noqa: BLE001 - cleanup after another failure
            pass

