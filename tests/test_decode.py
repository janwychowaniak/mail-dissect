"""The decoding rules of SPEC §7.2, tested directly.

These are written out in the specification precisely so that two implementations agree, so
they are tested as rules rather than only through a dissection that happens to exercise them.
"""

from __future__ import annotations

import base64

import pytest

from mail_dissect.decode import decode_text, decode_transfer, hash_bytes


@pytest.mark.parametrize(
    ("data", "declared", "expected_text", "expected_codec", "fallback"),
    [
        (b"plain", None, "plain", "utf-8", False),
        ("zażółć".encode(), "utf-8", "zażółć", "utf-8", False),
        ("zażółć".encode("iso-8859-2"), "iso-8859-2", "zażółć", "iso8859-2", False),
        # Declared wrongly: decoded with a deterministic codec, not a guessed one, and said so.
        ("zażółć".encode("iso-8859-2"), "utf-8", "za¿ó³æ", "cp1252", True),
        # A charset nobody has heard of is not a reason to lose the text.
        (b"plain", "x-nonsense", "plain", "utf-8", True),
        # Nor is one the lookup cannot even read: it raises ValueError, not LookupError (F17).
        (b"plain", "caf\udce9", "plain", "utf-8", True),
        (b"plain", "utf\x00", "plain", "utf-8", True),
        (b'"utf-8"', None, '"utf-8"', "utf-8", False),
    ],
)
def test_the_ladder(
    data: bytes, declared: str | None, expected_text: str, expected_codec: str, fallback: bool
) -> None:
    result = decode_text(data, declared)
    assert result.text == expected_text
    assert result.charset_used == expected_codec
    assert result.fallback is fallback


@pytest.mark.parametrize(
    ("bom", "codec"),
    [
        (b"\xef\xbb\xbf", "utf-8-sig"),
        (b"\xff\xfe", "utf-16-le"),
        (b"\xfe\xff", "utf-16-be"),
    ],
)
def test_a_bom_wins_outright(bom: bytes, codec: str) -> None:
    """Rung one: a BOM is the message telling us, and it beats the declaration."""
    encoded = "ok".encode(codec)
    result = decode_text(bom + encoded if not encoded.startswith(bom) else encoded, "iso-8859-1")
    assert result.charset_used.startswith(codec[:6])
    assert result.fallback is True  # it disagreed with what was declared


def test_html_meta_is_consulted_only_for_html() -> None:
    """Rung three exists because HTML carries its own declaration, and mail often lies."""
    data = b'<meta charset="iso-8859-2">za\xbf\xf3\xb3\xe6'
    as_html = decode_text(data, None, is_html=True)
    as_text = decode_text(data, None, is_html=False)
    assert as_html.charset_used == "iso8859-2"
    assert "zażółć" in as_html.text
    assert as_text.charset_used != "iso8859-2"


def test_the_ladder_always_terminates() -> None:
    """The last rung maps every byte, so no input can leave us without text."""
    result = decode_text(bytes(range(256)), "utf-8")
    assert len(result.text) == 256
    assert result.fallback is True


@pytest.mark.parametrize(
    ("payload", "encoding", "expected", "damaged"),
    [
        (b"plain", None, b"plain", False),
        (b"plain", "7bit", b"plain", False),
        (base64.b64encode(b"hello"), "base64", b"hello", False),
        (b"aGVsbG8=\r\n", "base64", b"hello", False),  # folded, as mail writes it
        (b"a=3Db", "quoted-printable", b"a=b", False),
        (b"", "base64", b"", False),
        # Damage: no padding makes a length of 1 mod 4 decodable.
        (b"QUJDR", "base64", None, True),
        (b"raw", "x-unknown-encoding", b"raw", True),
    ],
)
def test_transfer_decoding(
    payload: bytes, encoding: str | None, expected: bytes | None, damaged: bool
) -> None:
    decoded, was_damaged = decode_transfer(payload, encoding)
    assert decoded == expected
    assert was_damaged is damaged


def test_hashes_are_of_the_same_bytes() -> None:
    digests = hash_bytes(b"hello")
    assert digests.size == 5
    assert digests.md5 == "5d41402abc4b2a76b9719d911017c592"
    assert digests.sha256.startswith("2cf24dba5fb0")
