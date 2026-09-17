"""Detected type from the content signature, next to the declared one (SPEC §7.1).

The service does not comment on a discrepancy between the two — it returns both values and
lets the consumer decide what it means. The table is small and explicit rather than a
dependency on libmagic: one more C library reading hostile bytes, for a handful of signatures.
"""

from __future__ import annotations

_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"%PDF-", "application/pdf"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"BM", "image/bmp"),
    (b"II*\x00", "image/tiff"),
    (b"MM\x00*", "image/tiff"),
    (b"\x1f\x8b", "application/gzip"),
    (b"BZh", "application/x-bzip2"),
    (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed"),
    (b"Rar!\x1a\x07", "application/vnd.rar"),
    (b"MZ", "application/vnd.microsoft.portable-executable"),
    (b"\x7fELF", "application/x-elf"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/x-ole-storage"),
    (b"{\\rtf", "application/rtf"),
    (b"\xed\xab\xee\xdb", "application/x-rpm"),
    (b"\xca\xfe\xba\xbe", "application/java-vm"),
    (b"OggS", "application/ogg"),
    (b"fLaC", "audio/flac"),
    (b"\x00\x00\x01\x00", "image/vnd.microsoft.icon"),
)

_ZIP_PREFIXES = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")

# The office formats are ZIP containers; their real type shows in the first local file name.
_ZIP_MARKERS: tuple[tuple[bytes, str], ...] = (
    (b"word/", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
    (b"xl/", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
    (b"ppt/", "application/vnd.openxmlformats-officedocument.presentationml.presentation"),
    (b"mimetypeapplication/vnd.oasis.opendocument.text", "application/vnd.oasis.opendocument.text"),
    (
        b"mimetypeapplication/vnd.oasis.opendocument.spreadsheet",
        "application/vnd.oasis.opendocument.spreadsheet",
    ),
)

DOCUMENT_TYPES = frozenset(
    {
        "application/pdf",
        "application/rtf",
        "text/rtf",
        "application/msword",
        "application/vnd.ms-excel",
        "application/vnd.ms-powerpoint",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/vnd.oasis.opendocument.text",
        "application/vnd.oasis.opendocument.spreadsheet",
        "application/vnd.oasis.opendocument.presentation",
        "application/x-ole-storage",
    }
)


def detect_mime(data: bytes) -> str | None:
    """The type the bytes say they are, or None when they say nothing recognisable."""
    if not data:
        return None
    for signature, mime in _SIGNATURES:
        if data.startswith(signature):
            return mime
    if data[:4] in _ZIP_PREFIXES:
        window = data[:4096]
        for marker, mime in _ZIP_MARKERS:
            if marker in window:
                return mime
        return "application/zip"
    return None


def is_document(mime: str | None) -> bool:
    """Should this be offered to the text extractor? Only documents (SPEC §14.1).

    Never images, archives or executables: the tool is for pulling text out of documents, and
    handing it anything else is work with no result and a wider surface for no reason.
    """
    return mime is not None and mime.split(";")[0].strip().lower() in DOCUMENT_TYPES
