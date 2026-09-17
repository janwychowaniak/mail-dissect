"""Content signatures: SPEC §7.1, and which types go to the text extractor (§14.1)."""

from __future__ import annotations

import io
import zipfile

import pytest

from mail_dissect.sniff import detect_mime, is_document


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"%PDF-1.7 rest", "application/pdf"),
        (b"\x89PNG\r\n\x1a\n", "image/png"),
        (b"\xff\xd8\xff\xe0 jfif", "image/jpeg"),
        (b"GIF89a", "image/gif"),
        (b"MZ\x90\x00", "application/vnd.microsoft.portable-executable"),
        (b"\x7fELF\x02", "application/x-elf"),
        (b"{\\rtf1", "application/rtf"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/x-ole-storage"),
        (b"just text", None),
        (b"", None),
    ],
)
def test_signatures(data: bytes, expected: str | None) -> None:
    assert detect_mime(data) == expected


@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        ("word/document.xml", "…wordprocessingml.document"),
        ("xl/workbook.xml", "…spreadsheetml.sheet"),
        ("ppt/presentation.xml", "…presentationml.presentation"),
        ("hello.txt", "application/zip"),
    ],
)
def test_office_formats_are_zip_containers(entry: str, expected: str) -> None:
    """The type shows in the first file name inside the container, not in its header."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(entry, "<x/>")
    detected = detect_mime(buffer.getvalue())
    assert detected is not None
    assert detected.endswith(expected.lstrip("…"))


def test_only_documents_are_offered_to_the_extractor() -> None:
    """Never images, archives or executables (SPEC §14.1): work with no result, surface for
    no reason."""
    assert is_document("application/pdf")
    assert is_document("application/vnd.oasis.opendocument.text")
    assert is_document("APPLICATION/PDF; charset=binary")
    assert not is_document("image/png")
    assert not is_document("application/zip")
    assert not is_document("application/vnd.microsoft.portable-executable")
    assert not is_document(None)
