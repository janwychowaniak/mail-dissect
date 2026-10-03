"""A part's name: SPEC §6.4, `[D27]`. Acceptance cases 72 and 73.

The name is `filename` in `Content-Disposition`, or `name` in `Content-Type` where the first is
not written at all. Its plain form loses the white space between two adjacent encoded-words
and nothing else; its RFC 2231 form wins wherever it stands and is read in its charset and no
further. `mime_parts[].filename` and `attachments[].filename` show that one reading, and
`artifacts[].filename` and the served name show it after the sanitising of §13.3 and nothing
more.

Until 0.6.0 the plain form was decoded by the parser of `Content-Disposition`, handed the bare
name: it failed at the first `=` and recovered through the grammar of a display name, which
rewrote a `;` and what followed it as a parameter of its own, and which dropped the white space
between two encoded-words on one patch release of Python and kept it on another (F21).
"""

from __future__ import annotations

import base64
from urllib.parse import unquote

import builders as b
import pins
import pytest
from conftest import dissect
from fastapi.testclient import TestClient

TAB = "\t"
RESUME = "=?utf-8?Q?r=C3=A9sum=C3=A9?="  # résumé


def _b(text: str) -> str:
    return f"=?utf-8?B?{base64.b64encode(text.encode()).decode()}?="


def _named(client: TestClient, disposition: str | None, content_type: str = "") -> dict:
    raw = b.multipart(
        "mixed",
        b.part("text/plain", b"body"),
        b.part(content_type or "application/octet-stream", b"payload", disposition=disposition),
    )
    return dissect(client, raw)


def _name(client: TestClient, disposition: str | None, content_type: str = "") -> str | None:
    """The name, after checking that the two places that show it show the same one."""
    message = _named(client, disposition, content_type)["messages"][0]
    attachment = message["attachments"][0]
    assert attachment["filename"] == message["mime_parts"][2]["filename"]
    return attachment["filename"]


@pytest.mark.parametrize("case", pins.NAMED, ids=lambda case: case.file)
def test_a_saved_name(client: TestClient, case: pins.Named) -> None:
    """The saved shapes, on the developer's interpreter here and in the image by `pins.py`."""
    pins.check_named(case, lambda raw: dissect(client, raw))


@pytest.mark.parametrize(
    ("written", "name"),
    [
        # The white space between two adjacent encoded-words goes, wherever it stands.
        (f"{_b('naïve-no')} {_b('tes.txt')}", "naïve-notes.txt"),
        (f"{_b('naïve-no')}  {TAB} {_b('tes.txt')}", "naïve-notes.txt"),
        (f"{_b('naïve-notes.t')} {_b('xt')}", "naïve-notes.txt"),
        (f"{_b('naï')} {_b('ve-no')} {_b('tes.txt')}", "naïve-notes.txt"),
        ("=?utf-8?Q?na=C3=AFve-no?= =?iso-8859-1?Q?tes.txt?=", "naïve-notes.txt"),
        # A character whose bytes are split between two words is joined, not substituted.
        ("=?utf-8?Q?na=C3?= =?utf-8?Q?=AFve-notes.txt?=", "naïve-notes.txt"),
        # White space inside a word, or between a word and plain text, is the name's own.
        (f"{_b('naïve no')} {_b('tes.txt')}", "naïve notes.txt"),
        ("=?utf-8?Q?na=C3=AFve_?= =?utf-8?Q?notes.txt?=", "naïve notes.txt"),
        ("=?utf-8?Q?na=C3=AFve?= notes.txt", "naïve notes.txt"),
        ("old =?utf-8?Q?na=C3=AFve.txt?=", "old naïve.txt"),
        (f"{RESUME}  v2.pdf", "résumé  v2.pdf"),
        # Everything else stays as written: a `;` and what follows it are part of the name.
        (f"{RESUME};v2.pdf", "résumé;v2.pdf"),
        (f"{RESUME};x=y.pdf", "résumé;x=y.pdf"),
        (f"{RESUME};filename=other.pdf", "résumé;filename=other.pdf"),
        (f"{RESUME}; v2.pdf", "résumé; v2.pdf"),
        (f"{RESUME}=v2.pdf", "résumé=v2.pdf"),
        (f"{RESUME} (draft)", "résumé (draft)"),
        (f"{RESUME}(draft).pdf", "résumé(draft).pdf"),
        (f"{RESUME},v2.pdf", "résumé,v2.pdf"),
        (f"{RESUME}<v2>.pdf", "résumé<v2>.pdf"),
        (RESUME + '\\".pdf', 'résumé".pdf'),
        ("=?utf-8?Q?a=3Bb.pdf?=", "a;b.pdf"),
        ("=?utf-8?Q?a=3Db.pdf?=", "a=b.pdf"),
        ("=?utf-8?Q?a=22b.pdf?=", 'a"b.pdf'),
        (f"a{TAB}b.pdf", f"a{TAB}b.pdf"),
        # The controls: one word, and no word at all.
        (_b("naïve-notes.txt"), "naïve-notes.txt"),
        ("naive  notes.txt", "naive  notes.txt"),
    ],
)
def test_the_plain_form_is_read_as_unstructured_text(
    client: TestClient, written: str, name: str
) -> None:
    """RFC 2047 §6.2 and nothing more, on every interpreter (F21)."""
    assert _name(client, f'attachment; filename="{written}"') == name


@pytest.mark.parametrize(
    ("disposition", "content_type", "name"),
    [
        (
            "attachment; filename=\"plain.pdf\"; filename*=utf-8''r%C3%A9sum%C3%A9.pdf",
            "",
            "résumé.pdf",
        ),
        (
            "attachment; filename*=utf-8''r%C3%A9sum%C3%A9.pdf; filename=\"plain.pdf\"",
            "",
            "résumé.pdf",
        ),
        # A continued value is the RFC 2231 form too, with a charset or without one.
        (
            'attachment; filename="plain.pdf"; filename*0="contin"; filename*1="ued.pdf"',
            "",
            "continued.pdf",
        ),
        (
            None,
            "application/octet-stream; name=\"plain.pdf\"; name*=utf-8''r%C3%A9sum%C3%A9.pdf",
            "résumé.pdf",
        ),
        # `Content-Disposition` comes first in any form, and `name` is read only without it.
        (
            'attachment; filename="disposition.pdf"',
            "application/octet-stream; name*=utf-8''r%C3%A9sum%C3%A9.pdf",
            "disposition.pdf",
        ),
        ("inline", 'application/octet-stream; name="type.pdf"', "type.pdf"),
        # A second plain one is ignored, as the standard library's own accessor ignores it.
        ('attachment; filename="first.pdf"; filename="second.pdf"', "", "first.pdf"),
    ],
)
def test_the_rfc2231_form_wins_wherever_it_stands(
    client: TestClient, disposition: str | None, content_type: str, name: str
) -> None:
    """The plain form beside it is a stand-in for readers who do not know RFC 2231."""
    body = _named(client, disposition, content_type)
    assert body["messages"][0]["attachments"][0]["filename"] == name
    assert body["flags"] == []


def test_a_name_declared_with_a_charset_is_read_no_further(client: TestClient) -> None:
    """Percent-decoded in the declared charset, and that is the name, whatever it looks like.

    The control is the same text in the plain form, where an encoded-word is decoded.
    """
    written = "%3D%3Futf-8%3FQ%3Fr%3DC3%3DA9sum%3DC3%3DA9%3F%3D.pdf"
    assert _name(client, f"attachment; filename*=utf-8''{written}") == f"{RESUME}.pdf"
    assert _name(client, f'attachment; filename="{RESUME}.pdf"') == "résumé.pdf"
    # One segment with a charset makes the whole set the charset form: the others are taken
    # as written and joined, and nothing in them is decoded.
    mixed = "attachment; filename*0*=utf-8''na%C3%AFve-; filename*1=\"=?utf-8?Q?x?=.txt\""
    assert _name(client, mixed) == "naïve-=?utf-8?Q?x?=.txt"
    assert _name(client, "attachment; filename*0*=utf-8''na%C3%AFve-; filename*1=\"x.txt\"") == (
        "naïve-x.txt"
    )


@pytest.mark.parametrize(
    ("extended", "plain_beside_it", "name", "flags"),
    [
        ("x-unknown-charset''r%E9sum%E9.pdf", True, "plain.pdf", ["encoding_fallback"]),
        ("utf-8''r%E9sum%E9.pdf", True, "plain.pdf", ["encoding_fallback"]),
        # The controls: a declaration that holds is taken, and one that stands alone is read
        # as the standard library reads it, and reported as before.
        ("utf-8''r%C3%A9sum%C3%A9.pdf", True, "résumé.pdf", []),
        ("x-unknown-charset''cafe.pdf", False, "cafe.pdf", ["encoding_fallback"]),
    ],
)
def test_an_unreadable_charset_form_gives_way_to_the_plain_one_and_says_so(
    client: TestClient, extended: str, plain_beside_it: bool, name: str, flags: list[str]
) -> None:
    """SPEC §5.1: the material's declaration was not taken, which is what the flag says."""
    disposition = f"attachment; filename*={extended}"
    if plain_beside_it:
        disposition = f'attachment; filename="plain.pdf"; filename*={extended}'
    body = _named(client, disposition)
    assert body["messages"][0]["attachments"][0]["filename"] == name
    assert body["flags"] == flags


def test_the_flag_describes_what_was_read(client: TestClient) -> None:
    """SPEC §5.1, §6.4: a plain form beside the RFC 2231 form that is read is not read itself.

    On a part nothing else reads it, so an encoded-word in it that would not read cleanly raises
    nothing. The same header on the message is read by `headers{}`, which raises the flag there.
    The control is the plain form alone, which is the name, and is flagged on a part too.
    """
    unreadable = '"=?x-unknown-charset?Q?plain?=.pdf"'
    both = f"attachment; filename={unreadable}; filename*=utf-8''r%C3%A9sum%C3%A9.pdf"
    on_a_part = _named(client, both)
    assert on_a_part["messages"][0]["attachments"][0]["filename"] == "résumé.pdf"
    assert on_a_part["flags"] == []
    raw = b.message(
        {
            "From": "a@example.net",
            "Content-Type": "application/octet-stream",
            "Content-Disposition": both,
        },
        body=b"payload",
    )
    on_the_message = dissect(client, raw)
    assert on_the_message["messages"][0]["attachments"][0]["filename"] == "résumé.pdf"
    assert on_the_message["flags"] == ["encoding_fallback"]
    assert _named(client, f"attachment; filename={unreadable}")["flags"] == ["encoding_fallback"]


@pytest.mark.parametrize(
    ("disposition", "name"),
    [
        ('attachment; filename=" notes.pdf "', "notes.pdf"),
        (f'attachment; filename="{TAB}notes.pdf{TAB}"', "notes.pdf"),
        # The ends of the decoded name, not only of what was written.
        ('attachment; filename="=?utf-8?Q?_r=C3=A9sum=C3=A9.pdf_?="', "résumé.pdf"),
        ("attachment; filename*=utf-8''%20r%C3%A9sum%C3%A9.pdf%20", "résumé.pdf"),
        # A period at either end is a fact about the material and stays.
        ('attachment; filename="archive.exe."', "archive.exe."),
        ('attachment; filename=".profile"', ".profile"),
        ('attachment; filename=" .profile. "', ".profile."),
    ],
)
def test_white_space_at_the_ends_goes_and_a_period_stays(
    client: TestClient, disposition: str, name: str
) -> None:
    assert _name(client, disposition) == name


@pytest.mark.parametrize(
    ("name", "extension"),
    [
        ("notes.pdf", "pdf"),
        ("A.PDF", "pdf"),
        ("a.b.c", "c"),
        (".a.b", "b"),
        ("a..b", "b"),
        # No period, or one that is the first or the last character, means no extension.
        ("notes", None),
        (".profile", None),
        ("archive.exe.", None),
        ("name.", None),
        ("...", None),
        # The last path component is the one that counts, as for `pathlib`, after a `/` or a
        # `\\` alike: the sender's system is unknown. `filename` keeps the path as written.
        ("dir.d/file", None),
        ("../../etc/passwd", None),
        ("C:\\temp.d\\notes.PDF", "pdf"),
        ("C:\\temp.d\\notes", None),
        ("dir.d/", None),
        ("dir.d\\", None),
        ("dir/.profile", None),
        ("dir/.a.b", "b"),
    ],
)
def test_the_extension_follows_the_last_period_of_the_last_component(
    client: TestClient, name: str, extension: str | None
) -> None:
    """Acceptance case 73: `pathlib`'s convention, `.profile` and `archive.exe.` alike."""
    attachment = _named(client, f'attachment; filename="{name}"')["messages"][0]["attachments"][0]
    assert attachment["filename"] == name
    assert attachment["extension"] == extension


@pytest.mark.parametrize(
    ("written", "name", "served"),
    [
        (f"{RESUME};v2.pdf", "résumé;v2.pdf", "résumé;v2.pdf"),
        (f"{RESUME}  v2.pdf", "résumé  v2.pdf", "résumé v2.pdf"),
        ("archive.exe.", "archive.exe.", "archive.exe"),
        ("../reports/notes.pdf", "../reports/notes.pdf", "notes.pdf"),
    ],
)
def test_the_served_name_is_the_reading_after_sanitising_and_nothing_else(
    client: TestClient, written: str, name: str, served: str
) -> None:
    """SPEC §13.3: the fact is in the JSON; the header of the download is made safe from it."""
    body = _named(client, f'attachment; filename="{written}"')
    attachment = body["messages"][0]["attachments"][0]
    assert attachment["filename"] == name
    artifact = next(a for a in body["artifacts"] if a["artifact_id"] == attachment["artifact_id"])
    assert artifact["filename"] == served
    response = client.get(f"/v1/artifact/{body['dissect_id']}/{attachment['artifact_id']}")
    header = response.headers["content-disposition"]
    assert unquote(header.split("filename*=UTF-8''", 1)[1]) == served
