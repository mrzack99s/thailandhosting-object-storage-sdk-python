from __future__ import annotations


class ObjectStorageError(Exception):
    """An error answer from the service (a Problem Details document, RFC 9457).

    ``code`` is the machine-readable reason, for example
    ``object_not_found``, ``bucket_already_exists`` or ``busy``; ``message``
    is the document's ``title``.
    """

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(f"{code} (HTTP {status}): {message}")
        self.status = status
        self.code = code
        self.message = message


class NotFoundError(ObjectStorageError):
    """The bucket, object or upload does not exist."""


class PreconditionFailedError(ObjectStorageError):
    """``if_match`` / ``if_none_match`` (or ``if_unmodified_since``) did not
    hold: the object is not in the state the call asked for and nothing was
    written. HTTP 412, code ``precondition_failed``; never retried."""


class NotModifiedError(Exception):
    """``get(..., if_none_match=etag)`` (or ``if_modified_since``) matched: a
    cached copy is current."""


class IntegrityError(Exception):
    """What the service stored is not what was sent."""


class DigestMismatchError(IntegrityError):
    """A downloaded object does not match the SHA-256 the service reported
    for it (``Repr-Digest``): the data was damaged on the way."""
