# ThailandHosting Object Storage — Python SDK

Python client for ThailandHosting Object Storage: buckets, objects, large
files and share links over the ThailandHosting API.

```
pip install thailandhosting-object-storage
```

Python 3.9+. One dependency: `urllib3`.

## Quick start

```python
import os
from thailandhosting_objectstorage import Client, NotFoundError

client = Client(
    endpoint="https://objects.bkk.thailandhosting.com",
    access_key_id=os.environ["TH_ACCESS_KEY_ID"],
    secret_access_key=os.environ["TH_SECRET_ACCESS_KEY"],
)
bucket = client.bucket("my-bucket")

# Any size: large files go up as parallel parts.
bucket.upload_file("backups/db.dump", "/var/backups/db.dump")

# Large objects come down as parallel ranges.
bucket.download_file("backups/db.dump", "/tmp/db.dump")

# Small objects
bucket.put("notes/hello.txt", "สวัสดี", metadata={"author": "me"})
print(bucket.get_bytes("notes/hello.txt").decode())

# Streaming download
with bucket.get("videos/intro.mp4") as stream:
    for chunk in stream.iter_chunks():
        ...

# Every object under a prefix
for obj in bucket.iter_objects("backups/"):
    print(obj.key, obj.size)

# A link that works without a key for one hour
print(bucket.create_link("backups/db.dump", expires_in=3600).url)

try:
    bucket.head("missing")
except NotFoundError as e:
    print(e.code)  # object_not_found
```

Create access keys in the Console (Object Storage → Access keys). Reuse one
`Client` for the life of your program: it is thread-safe and keeps
connections open.

## Performance

| | |
|---|---|
| Connections | urllib3 pool, keep-alive; `pool_maxsize` (default `2 × concurrency`) |
| Uploads | `upload_file` reads parts straight from the file, one handle per thread, and sends them in parallel; `upload_fileobj` streams any binary stream (pipe, socket) holding at most `concurrency + 1` parts in memory |
| Downloads | `download_file` fetches parallel ranges into the file, each pinned to the object's ETag; `get` streams |
| Small data | one request; a stream that turns out small is one request too |
| Tuning | `part_size` (default 16 MiB), `concurrency` (default 8), `multipart_threshold` (default 32 MiB) |

Hashing and socket I/O release the GIL, so parts really move in parallel.

## Reliability

- Requests that are safe to repeat are retried with exponential backoff and
  jitter (`max_retries`, default 4) on 429, 500, 502, 503, 504 and
  connection errors.
- Every single upload and every part is checked against the MD5 the service
  reports; damaged data raises `IntegrityError` and is never accepted.
- A failed multipart upload is aborted, so its parts are not billed.
- `download_file` writes to `path + ".download"` and renames it into place;
  a range whose connection breaks resumes where it stopped.

## API

| `Client` | |
|---|---|
| `list_buckets()`, `create_bucket(name)`, `get_bucket(name)`, `delete_bucket(name)` | buckets |
| `bucket(name)` | a `Bucket` handle |

| `Bucket` | |
|---|---|
| `put`, `upload_file`, `upload_fileobj` | upload (`content_type`, `metadata`, `cache_control`, `content_disposition`, `if_not_exists`) |
| `get` (stream; `offset`/`length`, `if_none_match` → `NotModifiedError`, `if_match`), `get_bytes`, `download_file` | download |
| `head`, `exists`, `delete`, `delete_many`, `copy` | object operations |
| `list` (one page), `iter_objects` | listing |
| `create_link(key, expires_in=, upload=)` | a link that needs no key |
| `create_multipart_upload`, `resume_multipart_upload` → `upload_part`, `parts`, `complete`, `abort` | do-it-yourself multipart |

Errors from the service raise `ObjectStorageError` (`status`, `code`,
`message`); `NotFoundError` is the 404 case.

## Testing

```
python -m unittest -v tests/test_client.py
```

runs against an in-memory fake of the service. Set
`TH_OBJECT_STORAGE_ENDPOINT`, `TH_ACCESS_KEY_ID` and `TH_SECRET_ACCESS_KEY`
to also run a round trip against a real endpoint (it creates and deletes a
bucket).
