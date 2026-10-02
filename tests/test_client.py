"""Tests against an in-memory fake of the /v1 API, and (when
TH_OBJECT_STORAGE_ENDPOINT is set) against a real endpoint."""

import base64
import hashlib
import hmac
import io
import json
import os
import re
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thailandhosting_objectstorage import (  # noqa: E402
    Client,
    DigestMismatchError,
    IntegrityError,
    NotFoundError,
    NotModifiedError,
    ObjectStorageError,
    PreconditionFailedError,
    PublicRule,
)
from thailandhosting_objectstorage.client import _sign_request  # noqa: E402

MiB = 1 << 20
SECRETS = {"KEY": "SECRET"}
TITLES = {
    "unauthorized": "Sign the request with your access key (HTTP Message Signatures, RFC 9421).",
    "invalid_signature": "The request signature is not valid.",
    "bucket_already_exists": "The bucket name is taken.",
    "precondition_failed": "The object is not in the state If-Match / If-None-Match asked for.",
    "bad_digest": "The body does not match its Content-Digest (or Content-MD5).",
}


def md5hex(b):
    return hashlib.md5(b).hexdigest()


def sha256_digest(b):
    return "sha-256=:" + base64.b64encode(hashlib.sha256(b).digest()).decode() + ":"


def etag_matches(header, etag):
    """Whether an If-Match / If-None-Match list names etag (None: no object)."""
    if etag is None:
        return False
    for v in header.split(","):
        v = v.strip()
        if v.startswith("W/"):
            v = v[2:]
        if v == "*" or v.strip('"') == etag:
            return True
    return False


class Fake:
    def __init__(self):
        self.lock = threading.Lock()
        self.objects = {}
        self.types = {}
        self.reprs = {}  # oid: the Content-Digest it was uploaded with
        self.uploads = {}
        self.public = {}  # bucket: [{"prefix", "list"}]
        self.flaky = 0
        self.retry_after = None
        self.corrupt = False  # damage what is stored, after the digest check
        self.mangle = False  # damage bodies on the way in, before it
        self.damage_download = False
        self.inflight = 0
        self.max_inflight = 0
        self.requests = 0
        self.digests = []  # (method, path, Content-Digest, body) of every body
        self.signed = []  # (method, path, Signature-Input)
        self.headers_seen = []


def make_handler(fake):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def send_json(self, status, doc):
            data = json.dumps(doc).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def fail(self, status, code, extra=None):
            # Problem Details (RFC 9457); HEAD gets only X-Error-Code.
            self.send_response(status)
            self.send_header("X-Error-Code", code)
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            if self.command == "HEAD":
                self.send_header("Content-Length", "0")
                return self.end_headers()
            doc = {
                "type": "tag:thailandhosting.com,2026:object-storage/" + code,
                "title": TITLES.get(code, code),
                "status": status,
                "code": code,
                "instance": urlsplit(self.path).path,
            }
            data = json.dumps(doc).encode()
            self.send_header("Content-Type", "application/problem+json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def body(self):
            n = int(self.headers.get("Content-Length") or 0)
            return self.rfile.read(n) if n else b""

        def verify_signature(self):
            """Checks the RFC 9421 signature as the service does: rebuilds the
            signature base from the request as received and compares the
            HMAC. Returns None (good), or the error code."""
            m = re.fullmatch(r'th=\(([^)]*)\)(;created=(\d+);keyid="([^"]*)";alg="hmac-sha256")', self.headers.get("Signature-Input", ""))
            sig = re.fullmatch(r"th=:([A-Za-z0-9+/=]+):", self.headers.get("Signature", ""))
            if not m or not sig:
                return "invalid_signature"
            components = re.findall(r'"([^"]+)"', m.group(1))
            if abs(int(m.group(3)) - time.time()) > 300 or m.group(4) not in SECRETS:
                return "invalid_signature"
            if components[:4] != ["@method", "@authority", "@path", "@query"]:
                return "invalid_signature"
            if int(self.headers.get("Content-Length") or 0) > 0 and "content-digest" not in components:
                return "invalid_signature"
            u = urlsplit(self.path)
            host = self.headers["Host"].lower()
            for default in (":443", ":80"):
                if host.endswith(default):
                    host = host[: -len(default)]
            values = {"@method": self.command, "@authority": host, "@path": u.path or "/", "@query": "?" + u.query}
            lines = []
            for c in components:
                v = values.get(c, self.headers.get(c))
                if v is None:
                    return "invalid_signature"
                lines.append(f'"{c}": {v}')
            lines.append('"@signature-params": ' + m.group(0)[len("th="):])
            mac = hmac.new(SECRETS[m.group(4)].encode(), "\n".join(lines).encode(), hashlib.sha256).digest()
            if not hmac.compare_digest(mac, base64.b64decode(sig.group(1))):
                return "invalid_signature"
            with fake.lock:
                fake.signed.append((self.command, u.path, self.headers["Signature-Input"]))
            return None

        def handle_any(self):
            with fake.lock:
                fake.requests += 1
                fake.inflight += 1
                fake.max_inflight = max(fake.max_inflight, fake.inflight)
            try:
                self.route()
            finally:
                with fake.lock:
                    fake.inflight -= 1

        def public_read(self):
            # An unsigned GET or HEAD of an object a bucket made public.
            if self.command not in ("GET", "HEAD"):
                return False
            parts = urlsplit(self.path).path[len("/v1/buckets/"):].split("/", 2)
            if len(parts) != 3 or parts[1] != "objects":
                return False
            key = unquote(parts[2])
            return any(key.startswith(r["prefix"]) for r in fake.public.get(parts[0], []))

        def route(self):
            with fake.lock:
                fake.headers_seen.append(dict(self.headers))
            body = self.body()
            accept = {"Accept-Signature": 'th=("@method" "@authority" "@path" "@query" "content-digest");alg="hmac-sha256"'}
            if "Authorization" in self.headers:
                return self.fail(401, "unauthorized", accept)  # Bearer is gone
            if "Signature-Input" in self.headers:
                code = self.verify_signature()
                if code:
                    return self.fail(401, code, accept)
            elif not self.public_read():
                return self.fail(401, "unauthorized", accept)
            if fake.mangle and body:
                body = bytes([body[0] ^ 1]) + body[1:]
            cd = self.headers.get("Content-Digest")
            if cd is not None:
                with fake.lock:
                    fake.digests.append((self.command, urlsplit(self.path).path, cd, body))
                if cd != sha256_digest(body):
                    return self.fail(400, "bad_digest")
            with fake.lock:
                if fake.flaky > 0:
                    fake.flaky -= 1
                    return self.fail(503, "busy", {"Retry-After": fake.retry_after} if fake.retry_after else None)
            time.sleep(0.003)
            u = urlsplit(self.path)
            parts = u.path[len("/v1/buckets/"):].split("/", 2)
            bucket = parts[0]
            if len(parts) == 1 and self.command == "PUT":
                if bucket == "taken":
                    return self.fail(409, "bucket_already_exists")
                return self.send_json(200, {"name": bucket, "region": "th-bkk-1"})
            if len(parts) == 3 and parts[1] == "objects":
                return self.object(bucket, unquote(parts[2]), body)
            if len(parts) == 2 and parts[1] == "objects":
                return self.list(bucket, parse_qs(u.query))
            if len(parts) >= 2 and parts[1] == "uploads":
                return self.upload(bucket, parts, body)
            if len(parts) == 2 and parts[1] == "public":
                if self.command == "PUT":
                    fake.public[bucket] = json.loads(body)["rules"]
                return self.send_json(200, {"rules": fake.public.get(bucket, [])})
            self.fail(404, "not_found")

        def write_allowed(self, oid):
            """If-Match / If-None-Match on a write, as the service checks them
            atomically with it (the caller holds fake.lock)."""
            cur = fake.objects.get(oid)
            etag = md5hex(cur) if cur is not None else None
            im, inm = self.headers.get("If-Match"), self.headers.get("If-None-Match")
            if im is not None and not etag_matches(im, etag):
                return False
            return inm is None or not etag_matches(inm, etag)

        def object(self, bucket, key, body):
            oid = bucket + "/" + key
            if self.command == "PUT":
                if fake.corrupt and body:
                    body = bytes([body[0] ^ 1]) + body[1:]
                with fake.lock:
                    if not self.write_allowed(oid):
                        return self.fail(412, "precondition_failed")
                    fake.objects[oid] = body
                    fake.types[oid] = self.headers.get("Content-Type", "")
                    fake.reprs[oid] = self.headers.get("Content-Digest")
                return self.send_json(200, {"key": key, "size": len(body), "etag": md5hex(body)})
            if self.command == "DELETE":
                with fake.lock:
                    if not self.write_allowed(oid):
                        return self.fail(412, "precondition_failed")
                    fake.objects.pop(oid, None)
                self.send_response(204)
                self.send_header("Content-Length", "0")
                return self.end_headers()
            data = fake.objects.get(oid)
            if data is None:
                return self.fail(404, "object_not_found")
            etag = '"' + md5hex(data) + '"'
            if self.headers.get("If-Match") and not etag_matches(self.headers["If-Match"], etag.strip('"')):
                return self.fail(412, "precondition_failed")
            if self.headers.get("If-None-Match") and etag_matches(self.headers["If-None-Match"], etag.strip('"')):
                self.send_response(304)
                self.send_header("ETag", etag)
                return self.end_headers()
            start, end, status = 0, len(data) - 1, 200
            rng = self.headers.get("Range")
            if rng:
                a, _, b = rng[len("bytes="):].partition("-")
                start = int(a)
                if b:
                    end = min(int(b), len(data) - 1)
                status = 206
            self.send_response(status)
            self.send_header("ETag", etag)
            self.send_header("Content-Type", fake.types.get(oid, ""))
            if fake.reprs.get(oid):
                self.send_header("Repr-Digest", fake.reprs[oid])
            if status == 206:
                self.send_header("Content-Range", f"bytes {start}-{end}/{len(data)}")
            self.send_header("Content-Length", str(end - start + 1))
            self.end_headers()
            if self.command == "GET":
                out = data[start:end + 1]
                if fake.damage_download and out:
                    out = bytes([out[0] ^ 1]) + out[1:]
                self.wfile.write(out)

        def list(self, bucket, q):
            limit = int(q.get("limit", ["1000"])[0])
            after = base64.urlsafe_b64decode(q["cursor"][0] + "==").decode() if "cursor" in q else ""
            prefix = q.get("prefix", [""])[0]
            with fake.lock:
                keys = sorted(k[len(bucket) + 1:] for k in fake.objects if k.startswith(bucket + "/"))
            keys = [k for k in keys if k.startswith(prefix) and k > after]
            out = {"folders": []}
            if len(keys) > limit:
                keys = keys[:limit]
                out["nextCursor"] = base64.urlsafe_b64encode(keys[-1].encode()).decode().rstrip("=")
            out["objects"] = [{"key": k, "size": len(fake.objects[bucket + "/" + k])} for k in keys]
            self.send_json(200, out)

        def upload(self, bucket, parts, body):
            if len(parts) == 2:
                key = json.loads(body)["key"]
                with fake.lock:
                    uid = base64.urlsafe_b64encode(key.encode()).decode().rstrip("=") + "." + str(fake.requests)
                    fake.uploads[uid] = {}
                return self.send_json(201, {"uploadId": uid, "key": key})
            uid, _, sub = parts[2].partition("/")
            up = fake.uploads.get(uid)
            if up is None:
                return self.fail(404, "upload_not_found")
            key = base64.urlsafe_b64decode(uid.split(".")[0] + "==").decode()
            if sub.startswith("parts/"):
                n = int(sub[len("parts/"):])
                if fake.corrupt and body:
                    body = bytes([body[0] ^ 1]) + body[1:]
                with fake.lock:
                    up[n] = body
                return self.send_json(200, {"number": n, "etag": md5hex(body), "size": len(body)})
            if sub == "complete":
                want = json.loads(body or b"{}").get("parts") or [{"number": n, "etag": md5hex(d)} for n, d in sorted(up.items())]
                data = b"".join(up[p["number"]] for p in want)
                with fake.lock:
                    if not self.write_allowed(bucket + "/" + key):
                        return self.fail(412, "precondition_failed")
                    fake.objects[bucket + "/" + key] = data
                    fake.reprs.pop(bucket + "/" + key, None)  # joined parts have no digest
                    del fake.uploads[uid]
                return self.send_json(200, {"key": key, "size": len(data), "etag": "x-%d" % len(want)})
            if self.command == "DELETE":
                with fake.lock:
                    fake.uploads.pop(uid, None)
                self.send_response(204)
                self.send_header("Content-Length", "0")
                return self.end_headers()

        do_GET = do_PUT = do_POST = do_DELETE = do_HEAD = handle_any

    return H


class QuietServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass  # a client hanging up mid-request (an aborted upload) is expected


class FakeTest(unittest.TestCase):
    def setUp(self):
        self.fake = Fake()
        self.server = QuietServer(("127.0.0.1", 0), make_handler(self.fake))
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.client = Client(f"http://127.0.0.1:{self.server.server_port}", "KEY", "SECRET", part_size=5 * MiB, concurrency=4)
        self.bucket = self.client.bucket("b")
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.client.close()
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def test_put_get_escaping(self):
        key = "รูป/a b+c?#%.txt"
        self.bucket.put(key, "hello")
        self.assertIn("b/" + key, self.fake.objects)
        self.assertEqual(self.bucket.get_bytes(key), b"hello")
        self.assertEqual(self.fake.types["b/" + key], "text/plain")
        with self.assertRaises(NotFoundError) as e:
            self.bucket.get_bytes("missing")
        self.assertEqual(e.exception.code, "object_not_found")
        self.assertFalse(self.bucket.exists("missing"))

    def test_retries_busy(self):
        self.fake.flaky = 2
        self.bucket.put("k", b"data")
        self.assertEqual(self.fake.objects["b/k"], b"data")

    def test_detects_damaged_upload(self):
        self.fake.corrupt = True
        with self.assertRaises(IntegrityError):
            self.bucket.put("k", b"data")
        with self.assertRaises(IntegrityError):
            self.bucket.upload_fileobj("big", io.BytesIO(os.urandom(6 * MiB)))
        self.assertEqual(self.fake.uploads, {}, "damaged upload not aborted")

    def test_upload_file_parallel_and_download(self):
        data = os.urandom(3 * 5 * MiB + 77)
        src = os.path.join(self.tmp.name, "src.bin")
        with open(src, "wb") as f:
            f.write(data)
        self.fake.flaky = 3
        self.bucket.upload_file("file.bin", src)
        self.assertEqual(self.fake.objects["b/file.bin"], data)
        self.assertGreaterEqual(self.fake.max_inflight, 2, "parts not sent in parallel")
        self.fake.max_inflight = 0
        dst = os.path.join(self.tmp.name, "out", "dst.bin")
        self.bucket.download_file("file.bin", dst)
        with open(dst, "rb") as f:
            self.assertEqual(f.read(), data)
        self.assertGreaterEqual(self.fake.max_inflight, 2, "ranges not fetched in parallel")
        self.assertFalse(os.path.exists(dst + ".download"))

    def test_upload_fileobj_stream(self):
        data = os.urandom(5 * 5 * MiB + 1)
        self.bucket.upload_fileobj("s.bin", io.BufferedReader(io.BytesIO(data)))
        self.assertEqual(self.fake.objects["b/s.bin"], data)
        self.fake.requests = 0
        self.bucket.upload_fileobj("small.bin", io.BytesIO(b"tiny"))
        self.assertEqual(self.fake.requests, 1, "a small stream should be one request")

    def test_iter_objects(self):
        for i in range(25):
            self.fake.objects["b/p/%02d" % i] = b"x"
        keys = [o.key for o in self.bucket.iter_objects("p/", page_size=10)]
        self.assertEqual(keys, ["p/%02d" % i for i in range(25)])

    def test_range(self):
        self.bucket.put("r", bytes(range(100)))
        with self.bucket.get("r", offset=10, length=5) as s:
            self.assertEqual(s.read(), bytes(range(10, 15)))
            self.assertEqual(s.info.size, 100)

    def test_public_access(self):
        self.bucket.put("public/a b.txt", "hello")
        self.bucket.put("private/x.txt", "secret")
        rules = self.bucket.set_public_access([PublicRule("public/")])
        self.assertEqual(rules, [PublicRule("public/", False)])
        self.assertEqual(self.bucket.public_access(), rules)
        base = f"http://127.0.0.1:{self.server.server_port}"
        self.assertEqual(self.bucket.public_url("public/a b.txt"), base + "/b/public/a%20b.txt")
        # Without a key the client reads what is public, nothing else.
        anon = Client(base)
        try:
            self.assertEqual(anon.bucket("b").get_bytes("public/a b.txt"), b"hello")
            with self.assertRaises(ObjectStorageError):
                anon.bucket("b").get_bytes("private/x.txt")
        finally:
            anon.close()
        with self.assertRaises(ValueError):
            Client(base, "KEY")

    def test_signed_never_sends_secret(self):
        self.bucket.put("k", b"data")
        self.bucket.get_bytes("k")
        self.assertTrue(self.fake.signed)
        for h in self.fake.headers_seen:
            self.assertNotIn("Authorization", h)
            self.assertFalse(any("SECRET" in v for v in h.values()), h)
        # The body is covered on PUT, and not on GET.
        by_method = {m: si for m, _, si in self.fake.signed}
        self.assertIn('"content-digest")', by_method["PUT"])
        self.assertNotIn("content-digest", by_method["GET"])
        wrong = Client(f"http://127.0.0.1:{self.server.server_port}", "KEY", "WRONG")
        try:
            with self.assertRaises(ObjectStorageError) as e:
                wrong.bucket("b").put("k", b"x")
            self.assertEqual((e.exception.status, e.exception.code), (401, "invalid_signature"))
        finally:
            wrong.close()

    def test_body_digests(self):
        data = os.urandom(2 * 5 * MiB + 3)
        self.bucket.put("one", b"hello")
        self.bucket.put("empty", b"")
        self.bucket.upload_fileobj("parts", io.BytesIO(data))
        sent = {(m, p): cd for m, p, cd, _ in self.fake.digests}
        self.assertEqual(sent[("PUT", "/v1/buckets/b/objects/one")], sha256_digest(b"hello"))
        self.assertEqual(sent[("PUT", "/v1/buckets/b/objects/empty")], sha256_digest(b""))
        parts = sorted((p, cd) for m, p, cd, _ in self.fake.digests if "/parts/" in p)
        self.assertEqual([cd for _, cd in parts], [sha256_digest(data[:5 * MiB]), sha256_digest(data[5 * MiB:10 * MiB]), sha256_digest(data[10 * MiB:])])
        # JSON bodies (start and complete) carry one too; the fake checked them all.
        self.assertTrue(any(p.endswith("/complete") for _, p, _, _ in self.fake.digests))
        self.assertEqual(self.fake.objects["b/parts"], data)
        # A body damaged on the way is refused (400 bad_digest) and not retried.
        self.fake.mangle = True
        self.fake.requests = 0
        with self.assertRaises(ObjectStorageError) as e:
            self.bucket.put("k", b"data")
        self.assertEqual((e.exception.status, e.exception.code), (400, "bad_digest"))
        self.assertEqual(self.fake.requests, 1)
        self.assertNotIn("b/k", self.fake.objects)

    def test_problem_details(self):
        with self.assertRaises(ObjectStorageError) as e:
            self.client.create_bucket("taken")
        err = e.exception
        self.assertEqual((err.status, err.code, err.message), (409, "bucket_already_exists", "The bucket name is taken."))
        self.assertEqual(self.client.create_bucket("fresh").name, "fresh")
        # HEAD answers have no body: the code comes from X-Error-Code.
        with self.assertRaises(NotFoundError) as e:
            self.bucket.head("missing")
        self.assertEqual(e.exception.code, "object_not_found")

    def test_retry_after(self):
        self.fake.flaky = 1
        self.fake.retry_after = "1"
        t = time.monotonic()
        self.bucket.put("k", b"data")
        self.assertGreaterEqual(time.monotonic() - t, 0.95, "Retry-After not honoured")
        self.assertEqual(self.fake.objects["b/k"], b"data")
        # Each attempt is signed afresh (a later created).
        inputs = [si for m, p, si in self.fake.signed if p == "/v1/buckets/b/objects/k"]
        self.assertEqual(len(inputs), 2)
        self.assertNotEqual(inputs[0], inputs[1])

    def test_conditional_writes(self):
        info = self.bucket.put("k", b"v1", if_not_exists=True)
        self.fake.requests = 0
        with self.assertRaises(PreconditionFailedError) as e:
            self.bucket.put("k", b"v2", if_none_match="*")
        self.assertEqual((e.exception.status, e.exception.code), (412, "precondition_failed"))
        self.assertEqual(self.fake.requests, 1, "a 412 must not be retried")
        with self.assertRaises(PreconditionFailedError):
            self.bucket.put("k", b"v2", if_match="0" * 32)
        self.assertEqual(self.fake.objects["b/k"], b"v1")
        info = self.bucket.put("k", b"v2", if_match=info.etag)
        with self.assertRaises(PreconditionFailedError):
            self.bucket.delete("k", if_match=md5hex(b"v1"))
        # A large upload applies the condition when the parts are joined,
        # and the refused upload is aborted.
        src = os.path.join(self.tmp.name, "big.bin")
        with open(src, "wb") as f:
            f.write(os.urandom(11 * MiB))
        with self.assertRaises(PreconditionFailedError):
            self.bucket.upload_file("k", src, if_none_match="*")
        self.assertEqual(self.fake.uploads, {})
        self.assertEqual(self.fake.objects["b/k"], b"v2")
        self.bucket.upload_file("new-big", src, if_not_exists=True)
        self.bucket.delete("k", if_match=info.etag)
        self.assertNotIn("b/k", self.fake.objects)

    def test_conditional_reads(self):
        info = self.bucket.put("k", b"cached")
        with self.assertRaises(NotModifiedError):
            self.bucket.get("k", if_none_match=info.etag)
        with self.assertRaises(NotModifiedError):
            self.bucket.head("k", if_none_match=info.etag)
        with self.assertRaises(NotModifiedError):
            self.bucket.get_bytes("k", if_none_match=info.etag)
        self.assertEqual(self.bucket.get_bytes("k", if_none_match="other"), b"cached")
        with self.assertRaises(PreconditionFailedError):
            self.bucket.get("k", if_match="other")
        with self.assertRaises(PreconditionFailedError) as e:
            self.bucket.head("k", if_match="other")
        self.assertEqual(e.exception.code, "precondition_failed")
        with self.bucket.get("k", if_match=info.etag) as s:
            self.assertEqual(s.read(), b"cached")

    def test_repr_digest(self):
        data = os.urandom(1000)
        self.bucket.put("k", data)
        info = self.bucket.head("k")
        self.assertEqual(info.digest, sha256_digest(data))
        self.assertEqual(self.bucket.get_bytes("k"), data)
        with self.bucket.get("k") as s:
            self.assertEqual(b"".join(s.iter_chunks(100)), data)
        self.fake.damage_download = True
        with self.assertRaises(DigestMismatchError):
            self.bucket.get_bytes("k")
        with self.assertRaises(DigestMismatchError), self.bucket.get("k") as s:
            s.read()
        with self.assertRaises(DigestMismatchError), self.bucket.get("k") as s:
            for _ in s.iter_chunks(64):
                pass
        dst = os.path.join(self.tmp.name, "k.bin")
        with self.assertRaises(IntegrityError):
            self.bucket.download_file("k", dst)
        self.assertFalse(os.path.exists(dst) or os.path.exists(dst + ".download"))
        # A range is not the whole object: nothing to check it against.
        with self.bucket.get("k", offset=10, length=10) as s:
            self.assertEqual(len(s.read()), 10)
        # Parallel ranges are checked once the whole file is in.
        big = os.urandom(12 * MiB)
        self.fake.objects["b/big"] = big
        self.fake.reprs["b/big"] = sha256_digest(big)
        with self.assertRaises(DigestMismatchError):
            self.bucket.download_file("big", dst)
        self.assertFalse(os.path.exists(dst) or os.path.exists(dst + ".download"))
        self.fake.damage_download = False
        self.bucket.download_file("big", dst)
        with open(dst, "rb") as f:
            self.assertEqual(f.read(), big)


class SigningTest(unittest.TestCase):
    # Golden values from the service's reference signer (signForTest in
    # internal/objectapi/handler_test.go) for the same inputs.

    def test_put_with_body(self):
        cd = "sha-256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:"
        self.assertEqual(sha256_digest(b"hello world"), cd)
        si, sig, base = _sign_request(
            "PUT", "objects.th-bkk-1.thailandhosting.com", "/v1/buckets/photos/objects/a%20b.jpg", "", cd, "AKID", "s3cr3t", 1767225600
        )
        self.assertEqual(
            base,
            '"@method": PUT\n'
            '"@authority": objects.th-bkk-1.thailandhosting.com\n'
            '"@path": /v1/buckets/photos/objects/a%20b.jpg\n'
            '"@query": ?\n'
            '"content-digest": sha-256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:\n'
            '"@signature-params": ("@method" "@authority" "@path" "@query" "content-digest");created=1767225600;keyid="AKID";alg="hmac-sha256"',
        )
        self.assertEqual(si, 'th=("@method" "@authority" "@path" "@query" "content-digest");created=1767225600;keyid="AKID";alg="hmac-sha256"')
        self.assertEqual(sig, "th=:GaRnP2NjXKZgnFLdW2ZFru8v4+kZh44GytmT7502cm8=:")

    def test_get_with_query(self):
        si, sig, base = _sign_request(
            "GET", "objects.th-bkk-1.thailandhosting.com", "/v1/buckets/photos/objects", "prefix=a%2Fb&limit=10", None, "AKID", "s3cr3t", 1767225600
        )
        self.assertTrue(base.startswith('"@method": GET\n'))
        self.assertIn('"@query": ?prefix=a%2Fb&limit=10\n', base)
        self.assertEqual(si, 'th=("@method" "@authority" "@path" "@query");created=1767225600;keyid="AKID";alg="hmac-sha256"')
        self.assertEqual(sig, "th=:g0cpIX1saN7LcP5xygTxaj6qYfLi1qWgbKTxLTRGLcI=:")

    def test_authority(self):
        for endpoint, want in [
            ("https://Objects.Example.com", "objects.example.com"),
            ("https://objects.example.com:443/v1", "objects.example.com"),
            ("http://127.0.0.1:8080", "127.0.0.1:8080"),
        ]:
            c = Client(endpoint, "AKID", "s3cr3t")
            self.assertEqual(c._authority, want)
            c.close()


@unittest.skipUnless(os.environ.get("TH_OBJECT_STORAGE_ENDPOINT"), "TH_OBJECT_STORAGE_ENDPOINT is not set")
class IntegrationTest(unittest.TestCase):
    def test_round_trip(self):
        client = Client(os.environ["TH_OBJECT_STORAGE_ENDPOINT"], os.environ["TH_ACCESS_KEY_ID"], os.environ["TH_SECRET_ACCESS_KEY"])
        name = "sdk-py-it-%x" % (time.time_ns() % (1 << 32))
        client.create_bucket(name)
        bucket = client.bucket(name)
        try:
            with tempfile.TemporaryDirectory() as d:
                data = os.urandom(40 * MiB)
                src = os.path.join(d, "src.bin")
                with open(src, "wb") as f:
                    f.write(data)
                t = time.time()
                info = bucket.upload_file("big/file.bin", src, metadata={"origin": "python-sdk"})
                print(f"\nuploaded {info.size >> 20} MiB in {time.time() - t:.2f}s", file=sys.stderr)
                t = time.time()
                bucket.download_file("big/file.bin", os.path.join(d, "dst.bin"))
                print(f"downloaded in {time.time() - t:.2f}s", file=sys.stderr)
                with open(os.path.join(d, "dst.bin"), "rb") as f:
                    self.assertEqual(f.read(), data)
            self.assertEqual(bucket.head("big/file.bin").metadata.get("origin"), "python-sdk")
            bucket.put("notes/ไทย.txt", "สวัสดี")
            self.assertEqual(len(bucket.list(delimiter="/").folders), 2)
            bucket.copy("notes/ไทย.txt", "notes/copy.txt")
            link = bucket.create_link("notes/ไทย.txt", expires_in=60)
            with urllib.request.urlopen(link.url) as r:
                self.assertEqual(r.read().decode(), "สวัสดี")
        finally:
            bucket.delete_many([o.key for o in bucket.iter_objects()])
            client.delete_bucket(name)


if __name__ == "__main__":
    unittest.main()
