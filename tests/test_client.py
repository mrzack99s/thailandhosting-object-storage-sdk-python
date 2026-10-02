"""Tests against an in-memory fake of the /v1 API, and (when
TH_OBJECT_STORAGE_ENDPOINT is set) against a real endpoint."""

import base64
import hashlib
import io
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thailandhosting_objectstorage import Client, IntegrityError, NotFoundError  # noqa: E402

MiB = 1 << 20


def md5hex(b):
    return hashlib.md5(b).hexdigest()


class Fake:
    def __init__(self):
        self.lock = threading.Lock()
        self.objects = {}
        self.types = {}
        self.uploads = {}
        self.flaky = 0
        self.corrupt = False
        self.inflight = 0
        self.max_inflight = 0
        self.requests = 0


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

        def fail(self, status, code):
            self.send_json(status, {"error": {"code": code, "message": code}})

        def body(self):
            n = int(self.headers.get("Content-Length") or 0)
            return self.rfile.read(n) if n else b""

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

        def route(self):
            if self.headers.get("Authorization") != "Bearer KEY:SECRET":
                return self.fail(401, "unauthorized")
            body = self.body()
            with fake.lock:
                if fake.flaky > 0:
                    fake.flaky -= 1
                    return self.fail(503, "busy")
            time.sleep(0.003)
            u = urlsplit(self.path)
            parts = u.path[len("/v1/buckets/"):].split("/", 2)
            bucket = parts[0]
            if len(parts) == 3 and parts[1] == "objects":
                return self.object(bucket, unquote(parts[2]), body)
            if len(parts) == 2 and parts[1] == "objects":
                return self.list(bucket, parse_qs(u.query))
            if len(parts) >= 2 and parts[1] == "uploads":
                return self.upload(bucket, parts, body)
            self.fail(404, "not_found")

        def object(self, bucket, key, body):
            oid = bucket + "/" + key
            if self.command == "PUT":
                if fake.corrupt and body:
                    body = bytes([body[0] ^ 1]) + body[1:]
                with fake.lock:
                    fake.objects[oid] = body
                    fake.types[oid] = self.headers.get("Content-Type", "")
                return self.send_json(200, {"key": key, "size": len(body), "etag": md5hex(body)})
            if self.command == "DELETE":
                with fake.lock:
                    fake.objects.pop(oid, None)
                self.send_response(204)
                self.send_header("Content-Length", "0")
                return self.end_headers()
            data = fake.objects.get(oid)
            if data is None:
                return self.fail(404, "object_not_found")
            etag = '"' + md5hex(data) + '"'
            if self.headers.get("If-Match") and self.headers["If-Match"] != etag:
                return self.fail(412, "precondition_failed")
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
            if status == 206:
                self.send_header("Content-Range", f"bytes {start}-{end}/{len(data)}")
            self.send_header("Content-Length", str(end - start + 1))
            self.end_headers()
            if self.command == "GET":
                self.wfile.write(data[start:end + 1])

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
                    fake.objects[bucket + "/" + key] = data
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
