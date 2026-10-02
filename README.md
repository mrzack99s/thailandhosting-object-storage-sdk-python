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

## Authentication

Every request is signed with HTTP Message Signatures (RFC 9421),
HMAC-SHA256 keyed with your secret access key. The secret never leaves your
program: requests carry only the access key ID and the signature.

```
Content-Digest: sha-256=:<base64 SHA-256 of the body>:
Signature-Input: th=("@method" "@authority" "@path" "@query" "content-digest");created=<unix time>;keyid="<access key id>";alg="hmac-sha256"
Signature: th=:<base64 HMAC-SHA256>:
```

The signature covers the method, host, path and query, and the body's
Content-Digest (RFC 9530) whenever there is a body; the service checks the
digest against the bytes as they arrive. Each attempt is signed afresh, and
`created` must be within 5 minutes of the service's clock, so keep the
machine's time in sync (NTP). Share links (`create_link`) work without a key,
as before.

## Conditional writes and reads

```python
from thailandhosting_objectstorage import NotModifiedError, PreconditionFailedError

# Create only if the key is free (also on upload_file / upload_fileobj).
try:
    bucket.put("locks/job-42", b"me", if_none_match="*")
except PreconditionFailedError:
    print("someone else holds it")

# Replace or delete only the version you read (optimistic locking).
info = bucket.head("config.json")
bucket.put("config.json", new_config, if_match=info.etag)
bucket.delete("config.json", if_match=info.etag)

# Download only if it changed since your cached copy.
try:
    data = bucket.get_bytes("config.json", if_none_match=cached_etag)
except NotModifiedError:
    data = cached_data
```

The service checks `if_match` / `if_none_match` atomically with the write; a
large upload applies them when its parts are joined. `get`, `get_bytes` and
`head` also take `if_modified_since` / `if_unmodified_since`.

## Public buckets and folders

```python
from thailandhosting_objectstorage import Client, PublicRule

# Anyone may read images/ (and nothing else) without a key; needs a key
# allowed to manage buckets. [] makes the bucket private again.
bucket.set_public_access([PublicRule("images/")])
print(bucket.public_url("images/logo.png"))
# https://objects.bkk.thailandhosting.com/my-bucket/images/logo.png

# A client without a key reads (and, where allowed, lists) public objects.
anon = Client("https://objects.bkk.thailandhosting.com")
data = anon.bucket("my-bucket").get_bytes("images/logo.png")
```

What a key may do (buckets, folders, read / list / write / delete,
managing buckets, an expiry date) is set on the key in the Console.

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
  connection errors, waiting at least as long as `Retry-After` asks.
- Every body (each single upload, each part, each JSON request) carries its
  SHA-256 `Content-Digest`; the service refuses a body damaged on the way
  (`bad_digest`) and stores nothing. A stream that cannot seek is hashed
  from the buffer each part is read into. Every upload and part is also
  checked against the MD5 the service reports; damaged data raises
  `IntegrityError` and is never accepted.
- Objects uploaded in one request keep their digest, which `get` and `head`
  return as `info.digest` (`Repr-Digest`). Whole-object downloads (`get`,
  `get_bytes`, `download_file`) are checked against it and raise
  `DigestMismatchError` (an `IntegrityError`) on a mismatch. Ranges and
  objects uploaded in parts have no digest to check.
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
| `put`, `upload_file`, `upload_fileobj` | upload (`content_type`, `metadata`, `cache_control`, `content_disposition`, `if_not_exists`, `if_match`, `if_none_match`) |
| `get` (stream; `offset`/`length`), `get_bytes`, `download_file` | download (`if_none_match` / `if_modified_since` → `NotModifiedError`, `if_match` / `if_unmodified_since` → `PreconditionFailedError`) |
| `head`, `exists`, `delete` (`if_match`, `if_none_match`), `delete_many`, `copy` | object operations |
| `list` (one page), `iter_objects` | listing |
| `create_link(key, expires_in=, upload=)` | a link that needs no key |
| `public_access()`, `set_public_access(rules)`, `public_url(key)` | make the bucket or some folders readable by anyone, and their URLs |
| `create_multipart_upload`, `resume_multipart_upload` → `upload_part`, `parts`, `complete` (`if_match`, `if_none_match`), `abort` | do-it-yourself multipart |

Errors from the service are Problem Details (RFC 9457,
`application/problem+json`) and raise `ObjectStorageError` with `status`,
`code` (for example `object_not_found`, `bucket_already_exists`,
`invalid_signature`, `bad_digest`, `busy`) and `message` (the `title`).
`NotFoundError` is the 404 case and `PreconditionFailedError` the 412 case
(`precondition_failed`, never retried).

## Testing

```
python -m unittest -v tests/test_client.py
```

runs against an in-memory fake of the service. Set
`TH_OBJECT_STORAGE_ENDPOINT`, `TH_ACCESS_KEY_ID` and `TH_SECRET_ACCESS_KEY`
to also run a round trip against a real endpoint (it creates and deletes a
bucket).
