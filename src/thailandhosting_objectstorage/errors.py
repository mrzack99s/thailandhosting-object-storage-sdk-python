from __future__ import annotations


class ObjectStorageError(Exception):
    """An error answer from the service.

    ``code`` is the machine-readable reason, for example
    ``object_not_found``, ``bucket_already_exists`` or ``busy``.
    """

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(f"{code} (HTTP {status}): {message}")
        self.status = status
        self.code = code
        self.message = message


class NotFoundError(ObjectStorageError):
    """The bucket, object or upload does not exist."""


class NotModifiedError(Exception):
    """``get(..., if_none_match=etag)`` matched: a cached copy is current."""


class IntegrityError(Exception):
    """What the service stored is not what was sent."""
