"""Python SDK for ThailandHosting Object Storage.

    from thailandhosting_objectstorage import Client

    client = Client(
        endpoint="https://objects.bkk.thailandhosting.com",
        access_key_id=os.environ["TH_ACCESS_KEY_ID"],
        secret_access_key=os.environ["TH_SECRET_ACCESS_KEY"],
    )
    bucket = client.bucket("my-bucket")
    bucket.upload_file("backups/db.dump", "/var/backups/db.dump")

The client is thread-safe and should be reused: it keeps connections open.
Large uploads go up as parallel parts, large downloads come down as parallel
ranges, and requests that are safe to repeat are retried with backoff.
"""

from .client import (
    BucketInfo,
    Bucket,
    Client,
    Link,
    ListPage,
    MultipartUpload,
    ObjectInfo,
    ObjectStream,
    Part,
)
from .errors import IntegrityError, NotFoundError, NotModifiedError, ObjectStorageError

__version__ = "1.0.0"

__all__ = [
    "Bucket",
    "BucketInfo",
    "Client",
    "IntegrityError",
    "Link",
    "ListPage",
    "MultipartUpload",
    "NotFoundError",
    "NotModifiedError",
    "ObjectInfo",
    "ObjectStorageError",
    "ObjectStream",
    "Part",
]
