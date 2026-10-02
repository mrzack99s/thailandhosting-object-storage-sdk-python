from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import mimetypes
import os
import random
import threading
import time
from concurrent.futures import FIRST_EXCEPTION, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import format_datetime, parsedate_to_datetime
from typing import IO, Any, Callable, Dict, Iterator, List, Mapping, Optional, Sequence, Tuple, Union
from urllib.parse import quote, urlencode, urlsplit

import urllib3
from urllib3.util import parse_url

from .errors import DigestMismatchError, IntegrityError, NotFoundError, NotModifiedError, ObjectStorageError, PreconditionFailedError

__all__ = ["Client", "Bucket", "MultipartUpload"]

VERSION = "1.0.0"
MiB = 1 << 20
MIN_PART_SIZE = 5 * MiB
MAX_PARTS = 10000

Body = Union[bytes, bytearray, memoryview, str]
# An HTTP date for if_modified_since / if_unmodified_since: a datetime (naive
# means UTC) or the header value itself.
When = Union[datetime, str]


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
    # The object's Repr-Digest (RFC 9530), e.g. "sha-256=:<base64>:", from
    # get and head; "" for objects uploaded in parts. Full downloads are
    # checked against it.
    digest: str = ""

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
            digest=headers.get("Repr-Digest", ""),
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


# ---- HTTP Message Signatures (RFC 9421) and digests (RFC 9530) ----

_SIGNATURE_LABEL = "th"


def _content_digest(data: bytes) -> str:
    """The Content-Digest (RFC 9530) of a body."""
    return "sha-256=:" + base64.b64encode(hashlib.sha256(data).digest()).decode() + ":"


def _sha256_of(digest: str) -> Optional[bytes]:
    """The sha-256 member of a Content-Digest / Repr-Digest value, if any."""
    for member in digest.split(","):
        name, _, value = member.split(";", 1)[0].strip().partition("=")
        value = value.strip()
        if name.strip().lower() == "sha-256" and len(value) > 2 and value[0] == value[-1] == ":":
            try:
                return base64.b64decode(value[1:-1], validate=True)
            except (binascii.Error, ValueError):
                return None
    return None


def _sf_string(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _sign_request(
    method: str,
    authority: str,
    path: str,
    query: str,
    content_digest: Optional[str],
    key_id: str,
    secret: str,
    created: int,
) -> Tuple[str, str, str]:
    """Signs one request with HMAC-SHA256 under the secret, which is never
    sent. Returns (Signature-Input, Signature, the signature base). ``path``
    and ``query`` are exactly as on the request line (percent-encoded, the
    query without its "?"); ``content_digest`` is the Content-Digest header
    sent with a body, or None without one."""
    components = ["@method", "@authority", "@path", "@query"]
    values = [method.upper(), authority, path or "/", "?" + query]
    if content_digest is not None:
        components.append("content-digest")
        values.append(content_digest)
    params = "(" + " ".join(_sf_string(c) for c in components) + ")"
    params += f";created={int(created)};keyid={_sf_string(key_id)};alg=\"hmac-sha256\""
    lines = [f"{_sf_string(c)}: {v}" for c, v in zip(components, values)]
    lines.append('"@signature-params": ' + params)
    base = "\n".join(lines)
    mac = hmac.new(secret.encode(), base.encode(), hashlib.sha256).digest()
    return f"{_SIGNATURE_LABEL}={params}", f"{_SIGNATURE_LABEL}=:{base64.b64encode(mac).decode()}:", base


def _authority(netloc: str) -> str:
    """@authority: the Host header as sent, lower case, without :443 / :80."""
    host = netloc.rpartition("@")[2].lower()
    for default in (":443", ":80"):
        if host.endswith(default):
            host = host[: -len(default)]
    return host


# ---- conditional requests (RFC 9110) ----


def _etag_list(value: str) -> str:
    """An If-Match / If-None-Match value: "*", or ETags (bare or quoted,
    comma-separated) each quoted."""
    if value.strip() == "*":
        return "*"
    out = []
    for v in value.split(","):
        v = v.strip()
        if not v:
            continue
        if not (v.startswith('W/"') or (len(v) > 1 and v[0] == v[-1] == '"')):
            v = '"' + v.strip('"') + '"'
        out.append(v)
    return ", ".join(out)


def _http_date(when: When) -> str:
    if isinstance(when, str):
        return when
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return format_datetime(when.astimezone(timezone.utc), usegmt=True)


def _cond_headers(
    if_match: Optional[str] = None,
    if_none_match: Optional[str] = None,
    if_modified_since: Optional[When] = None,
    if_unmodified_since: Optional[When] = None,
) -> Dict[str, str]:
    h: Dict[str, str] = {}
    if if_match:
        h["If-Match"] = _etag_list(if_match)
    if if_none_match:
        h["If-None-Match"] = _etag_list(if_none_match)
    if if_modified_since is not None:
        h["If-Modified-Since"] = _http_date(if_modified_since)
    if if_unmodified_since is not None:
        h["If-Unmodified-Since"] = _http_date(if_unmodified_since)
    return h


def _check_digest(want: Optional[bytes], got: bytes, key: str) -> None:
    if want is not None and not hmac.compare_digest(want, got):
        raise DigestMismatchError(
            f"{key}: the downloaded data does not match its Repr-Digest "
            f"(sha-256 {base64.b64encode(want).decode()}, got {base64.b64encode(got).decode()})"
        )


class ObjectStream:
    """A download in progress. Iterate with ``iter_chunks()``, ``read()`` it,
    or use it as a context manager; close it when done. A whole-object
    download that carries a Repr-Digest is checked as it is read: reading the
    last byte raises ``DigestMismatchError`` when the data was damaged."""

    def __init__(self, response: urllib3.BaseHTTPResponse, info: ObjectInfo, verify: bool = False) -> None:
        self._resp = response
        self.info = info
        self.content_range = response.headers.get("Content-Range")
        self._want = _sha256_of(info.digest) if verify else None
        self._hash = hashlib.sha256() if self._want is not None else None
        self._seen = 0

    def _feed(self, data: bytes) -> None:
        if self._hash is None:
            return
        self._hash.update(data)
        self._seen += len(data)
        if self._seen >= self.info.size:
            self._finish()

    def _finish(self) -> None:
        if self._hash is not None:
            h, self._hash = self._hash, None
            _check_digest(self._want, h.digest(), self.info.key)

    def read(self, amt: Optional[int] = None) -> bytes:
        data = self._resp.read(amt)
        if data:
            self._feed(data)
        if amt is None or (not data and amt):
            self._finish()
        return data

    def iter_chunks(self, chunk_size: int = 1 * MiB) -> Iterator[bytes]:
        for chunk in self._resp.stream(chunk_size):
            self._feed(chunk)
            yield chunk
        self._finish()

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
        # Requests are signed (HTTP Message Signatures, RFC 9421); the secret
        # itself never leaves this process.
        self._key_id = access_key_id
        self._secret = secret_access_key
        self._authority = _authority(u.netloc)
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
        if headers:
            h.update(headers)
        if body is None and method in ("PUT", "POST"):
            body = b""
        if body is not None:
            # Every body carries its digest (RFC 9530), known before it is
            # sent: bodies here are always in memory. The service checks it
            # against the bytes as they arrive and stores nothing on a
            # mismatch (400 bad_digest).
            body = body.encode() if isinstance(body, str) else bytes(body)
            h["Content-Digest"] = _content_digest(body)
        # The path and query exactly as urllib3 puts them on the request line.
        target = parse_url(url)
        attempt = 0
        while True:
            if self._key_id:
                # Signed afresh on every attempt: created must be recent.
                h["Signature-Input"], h["Signature"], _ = _sign_request(
                    method, self._authority, target.path or "/", target.query or "", h.get("Content-Digest"), self._key_id, self._secret, int(time.time())
                )
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
            # Retry-After (seconds; 503 busy sends 1) is the least we wait.
            try:
                d = max(d, min(float(retry_after), 30.0))
            except ValueError:
                pass
        time.sleep(d)

    @staticmethod
    def _error(resp: urllib3.BaseHTTPResponse) -> ObjectStorageError:
        data = resp.data if resp.data is not None else b""
        resp.release_conn()
        # Problem Details (RFC 9457): {"type","title","status","code","instance"}.
        # A HEAD answer has no body; its code is in X-Error-Code.
        code = resp.headers.get("X-Error-Code") or ""
        message = resp.reason or ""
        try:
            doc = json.loads(data or b"{}")
            code, message = doc.get("code") or code, doc.get("title") or message
        except (ValueError, AttributeError):
            pass
        code = str(code or (resp.reason or "error").lower().replace(" ", "_"))
        cls = {404: NotFoundError, 412: PreconditionFailedError}.get(resp.status, ObjectStorageError)
        return cls(resp.status, code, str(message))

    def _json(
        self,
        method: str,
        path: str,
        payload: Any = None,
        *,
        query: Optional[Mapping[str, Any]] = None,
        retry_post: bool = False,
        headers: Optional[Mapping[str, str]] = None,
    ) -> Any:
        body = None
        h: Dict[str, str] = dict(headers or {})
        if payload is not None:
            body = json.dumps(payload).encode()
            h["Content-Type"] = "application/json"
        resp = self._request(method, path, query=query, headers=h, body=body, retry_post=retry_post)
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
    if_match: Optional[str] = None,
    if_none_match: Optional[str] = None,
) -> Dict[str, str]:
    h = _write_conds(if_not_exists, if_match, if_none_match)
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
    return h


def _write_conds(if_not_exists: bool, if_match: Optional[str], if_none_match: Optional[str]) -> Dict[str, str]:
    """The conditions of a write, which the service checks atomically with
    it: ``if_not_exists`` is ``if_none_match="*"`` (create only)."""
    return _cond_headers(if_match, "*" if if_not_exists else if_none_match)


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
        if_match: Optional[str] = None,
        if_none_match: Optional[str] = None,
    ) -> ObjectInfo:
        """Upload ``data`` (bytes or str) in one request. Use ``upload_file``
        or ``upload_fileobj`` for large or streamed data.

        ``if_match`` (ETags or ``"*"``) writes only over that version;
        ``if_none_match="*"`` (or ``if_not_exists=True``) only when the key is
        free. Otherwise nothing is written and ``PreconditionFailedError`` is
        raised."""
        if isinstance(data, str):
            data = data.encode()
        headers = _put_headers(
            content_type or _guess_type(key), metadata, cache_control, content_disposition, content_encoding, if_not_exists, if_match, if_none_match
        )
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
        if_modified_since: Optional[When] = None,
        if_unmodified_since: Optional[When] = None,
    ) -> ObjectStream:
        """Stream an object (or ``length`` bytes from ``offset``). Close the
        stream, or use ``with``. ``info.size`` is the whole object's size.

        ``if_none_match`` / ``if_modified_since`` raise ``NotModifiedError``
        when a cached copy is current; ``if_match`` / ``if_unmodified_since``
        raise ``PreconditionFailedError`` when the object changed. A whole
        object is checked against its Repr-Digest as it is read."""
        headers = _cond_headers(if_match, if_none_match, if_modified_since, if_unmodified_since)
        if offset or length:
            headers["Range"] = f"bytes={offset}-{offset + length - 1}" if length else f"bytes={offset}-"
        resp = self._c._request("GET", self._obj(key), headers=headers, stream=True, expect=(200, 206, 304))
        if resp.status == 304:
            resp.release_conn()
            raise NotModifiedError(key)
        return ObjectStream(resp, ObjectInfo._from_headers(key, resp.headers), verify=resp.status == 200)

    def get_bytes(
        self,
        key: str,
        *,
        if_none_match: Optional[str] = None,
        if_match: Optional[str] = None,
        if_modified_since: Optional[When] = None,
        if_unmodified_since: Optional[When] = None,
    ) -> bytes:
        """Download a whole object into memory, checked against its
        Repr-Digest. Conditions as for ``get``."""
        headers = _cond_headers(if_match, if_none_match, if_modified_since, if_unmodified_since)
        resp = self._c._request("GET", self._obj(key), headers=headers, expect=(200, 304))
        if resp.status == 304:
            raise NotModifiedError(key)
        data = resp.data
        want = _sha256_of(resp.headers.get("Repr-Digest", ""))
        if want is not None:
            _check_digest(want, hashlib.sha256(data).digest(), key)
        return data

    def head(
        self,
        key: str,
        *,
        if_none_match: Optional[str] = None,
        if_match: Optional[str] = None,
        if_modified_since: Optional[When] = None,
        if_unmodified_since: Optional[When] = None,
    ) -> ObjectInfo:
        """The object's size, ETag, type, metadata and digest. Conditions as
        for ``get``."""
        headers = _cond_headers(if_match, if_none_match, if_modified_since, if_unmodified_since)
        resp = self._c._request("HEAD", self._obj(key), headers=headers, expect=(200, 304))
        if resp.status == 304:
            raise NotModifiedError(key)
        return ObjectInfo._from_headers(key, resp.headers)

    def exists(self, key: str) -> bool:
        try:
            self.head(key)
            return True
        except NotFoundError:
            return False

    def delete(self, key: str, *, if_match: Optional[str] = None, if_none_match: Optional[str] = None) -> None:
        """Delete an object; deleting a missing one succeeds (unless
        ``if_match`` asked for a version). ``if_match`` deletes only that
        version, else ``PreconditionFailedError``."""
        self._c._request("DELETE", self._obj(key), headers=_cond_headers(if_match, if_none_match))

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
        if_not_exists: bool = False,
        if_match: Optional[str] = None,
        if_none_match: Optional[str] = None,
    ) -> ObjectInfo:
        """Upload a local file. Large files go up as parts read from the file
        and sent in parallel; each part is re-read if it must be sent again.
        Conditions as for ``put``; a large upload applies them when its parts
        are joined, and is aborted when they do not hold."""
        path = os.fspath(path)
        size = os.path.getsize(path)
        content_type = content_type or _guess_type(path)
        if if_not_exists:
            if_none_match = "*"
        if size <= self._c.multipart_threshold:
            with open(path, "rb") as f:
                return self.put(
                    key,
                    f.read(),
                    content_type=content_type,
                    metadata=metadata,
                    cache_control=cache_control,
                    content_disposition=content_disposition,
                    if_match=if_match,
                    if_none_match=if_none_match,
                )
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
            return up.complete(parts, if_match=if_match, if_none_match=if_none_match)
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
        if_not_exists: bool = False,
        if_match: Optional[str] = None,
        if_none_match: Optional[str] = None,
    ) -> ObjectInfo:
        """Upload what a binary stream yields (a pipe, a socket, a generated
        export) without knowing its size. Parts are read one after another and
        sent in parallel, holding at most ``concurrency + 1`` in memory. Each
        request's Content-Digest is hashed from that buffer, so the stream need
        not be seekable. Conditions as for ``upload_file``."""
        if if_not_exists:
            if_none_match = "*"
        ps = self._c.part_size
        first = _read_full(fileobj, ps)
        if len(first) < ps:
            return self.put(key, first, content_type=content_type, metadata=metadata, if_match=if_match, if_none_match=if_none_match)
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
            return up.complete(parts, if_match=if_match, if_none_match=if_none_match)
        except BaseException:
            up._abort_quietly()
            raise

    def download_file(self, key: str, path: Union[str, "os.PathLike[str]"]) -> ObjectInfo:
        """Save an object to ``path``. Large objects come down as parallel
        ranges pinned to the object's ETag. The data is written to
        ``path + '.download'``, checked against the object's Repr-Digest
        (``DigestMismatchError``) and renamed into place."""
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
                # The ranges arrive out of order: check the whole file once
                # they are all in (objects uploaded in parts have no digest).
                want = _sha256_of(info.digest)
                if want is not None:
                    _check_digest(want, _sha256_file(tmp), key)
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


def _sha256_file(path: str) -> bytes:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(MiB), b""):
            h.update(chunk)
    return h.digest()


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
        least 5 MiB. Sending a number again replaces that part. The part
        carries its own Content-Digest."""
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

    def complete(self, parts: Optional[Sequence[Part]] = None, *, if_match: Optional[str] = None, if_none_match: Optional[str] = None) -> ObjectInfo:
        """Join the parts into the object; without ``parts``, every part
        received, in order. ``if_match`` / ``if_none_match`` are checked
        atomically with the join (``PreconditionFailedError``: the object is
        not written)."""
        payload = None
        if parts is not None:
            payload = {"parts": [{"number": p.number, "etag": p.etag} for p in sorted(parts, key=lambda p: p.number)]}
        try:
            return ObjectInfo._from(
                self.bucket._c._json("POST", self._path() + "/complete", payload, retry_post=True, headers=_cond_headers(if_match, if_none_match))
            )
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

