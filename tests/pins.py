"""What the service reads out of a header, pinned to the interpreter that does the reading.

`headers{}` and `addresses{}` are the standard library's header parser at work `[D24]`, and
that parser moves between patch releases of Python: what it makes of a malformed address was
one mailbox on 3.13.12 and two on 3.13.15, with the same defect either way `[D25]`. A part's
name is read with the same library `[D27]`, and the grammar it was once read with dropped the
white space between two encoded-words on 3.13.15 and kept it on 3.13.12 (F21). So these
expectations have two homes: the suite runs them on the developer's interpreter, and CI runs
this file inside the built image, on the interpreter that is actually published:

    docker run --rm -v "$PWD/tests:/tests:ro" mail-dissect:ci python /tests/pins.py

Nothing here may need more than the image carries — the standard library, the service, and
the test client the service's own dependencies provide.
"""

from __future__ import annotations

import re
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from email.headerregistry import UnstructuredHeader
from pathlib import Path
from typing import Any

REGRESSIONS = Path(__file__).parent / "regressions"

Dissect = Callable[[bytes], dict[str, Any]]

# The header registry's map as the service uses it: the standard library's own, plus the two
# address headers of F6. Every name outside it is unstructured. SPEC §7 lists the structured
# ones by name, and a Python that maps a header differently must turn this red, not quietly
# change what `headers{}` returns for it.
REGISTRY_MAP = {
    "bcc": "UniqueAddressHeader",
    "cc": "UniqueAddressHeader",
    "content-disposition": "ContentDispositionHeader",
    "content-transfer-encoding": "ContentTransferEncodingHeader",
    "content-type": "ContentTypeHeader",
    "date": "UniqueDateHeader",
    "from": "UniqueAddressHeader",
    "in-reply-to": "ReferencesHeader",
    "message-id": "MessageIDHeader",
    "mime-version": "MIMEVersionHeader",
    "orig-date": "UniqueDateHeader",
    "references": "ReferencesHeader",
    "reply-to": "UniqueAddressHeader",
    "resent-bcc": "AddressHeader",
    "resent-cc": "AddressHeader",
    "resent-date": "DateHeader",
    "resent-from": "AddressHeader",
    "resent-reply-to": "AddressHeader",
    "resent-sender": "SingleAddressHeader",
    "resent-to": "AddressHeader",
    "return-path": "UniqueAddressHeader",
    "sender": "UniqueSingleAddressHeader",
    "subject": "UniqueUnstructuredHeader",
    "to": "UniqueAddressHeader",
}
UNSTRUCTURED = {"subject"}
STRUCTURED_HEADERS = frozenset(REGISTRY_MAP) - UNSTRUCTURED


def _address(display_name: str | None, address: str) -> dict[str, str | None]:
    local_part, _, domain = address.rpartition("@")
    return {
        "display_name": display_name,
        "address": address,
        "local_part": local_part,
        "domain": domain,
    }


@dataclass(frozen=True)
class Folded:
    """One saved message with folded headers, and what its headers say once unfolded."""

    file: str
    # Every line break in the file that is a fold, at every level. The twin is made by
    # removing exactly these, and the count is what shows that it removed nothing else.
    folds: int
    headers: dict[str, list[str]]
    addresses: dict[str, list[dict[str, str | None]]] = field(default_factory=dict)
    # Which message the expectations describe: 0 is the top level, 1 the first nested one.
    message: int = 0

    @property
    def raw(self) -> bytes:
        return (REGRESSIONS / self.file).read_bytes()


_TAB = "\t"

FOLDED: tuple[Folded, ...] = (
    Folded(
        "2026-09-30-folded-from-encoded-word.eml",
        folds=1,
        headers={"from": ["Łódź Testowy <sender@example.net>"]},
        addresses={"from": [_address("Łódź Testowy", "sender@example.net")]},
    ),
    Folded(
        "2026-09-30-folded-from.eml",
        folds=1,
        headers={"from": ["Alice Example <alice@example.net>"]},
        addresses={"from": [_address("Alice Example", "alice@example.net")]},
    ),
    Folded(
        "2026-09-30-folded-from-bare-lf.eml",
        folds=1,
        headers={"from": ["Alice Example <alice@example.net>"]},
        addresses={"from": [_address("Alice Example", "alice@example.net")]},
    ),
    Folded(
        "2026-09-30-folded-to-two-addresses.eml",
        folds=1,
        headers={
            "to": ["First Recipient <first@example.org>, Second Recipient <second@example.org>"]
        },
        addresses={
            "to": [
                _address("First Recipient", "first@example.org"),
                _address("Second Recipient", "second@example.org"),
            ]
        },
    ),
    Folded(
        "2026-09-30-folded-subject-two-encoded-words.eml",
        folds=1,
        # RFC 2047 §6.2: the white space between two encoded-words is not part of the text.
        # The one space left is the second word's own, inside its payload.
        headers={"subject": ["Zakończone sprawdzanie slowa druga polowa"]},
    ),
    Folded(
        "2026-09-30-folded-subject.eml",
        folds=1,
        headers={"subject": ["first half second half"]},
    ),
    Folded(
        "2026-09-30-folded-received.eml",
        folds=2,
        # RFC 5322 §2.2.3: the line break goes, the white space that followed it stays.
        headers={
            "received": [
                "from mx.example.net (mx.example.net [192.0.2.10])"
                f"{_TAB}by mail.example.org with ESMTPS id abc123"
                f"{_TAB}for <recipient@example.org>; Tue, 30 Sep 2026 10:00:00 +0200"
            ]
        },
    ),
    Folded(
        "2026-09-30-folded-inside-a-timestamp-and-a-parameter.eml",
        folds=4,
        headers={
            "received": [
                "from mx.example.net (mx.example.net [192.0.2.10]) by mail.example.org"
                f"{_TAB}with ESMTPS id abc123; Wed, 30 Sep 2026 10:00:00 +0200{_TAB}(CEST)",
                "from origin.example.net by mx.example.net with ESMTP id def456;"
                " Wed, 30 Sep 2026 09:59:58 +0200",
            ],
            "authentication-results": [
                'mx.example.org; dkim=fail reason="bad signature" header.d=example.net'
            ],
        },
    ),
    Folded(
        "2026-09-30-folded-content-type.eml",
        folds=1,
        headers={"content-type": ['text/plain; charset="iso-8859-2"']},
    ),
    Folded(
        "2026-09-30-folded-subject-splits-a-domain.eml",
        folds=1,
        headers={"subject": ["Zobacz example.com teraz"]},
    ),
    Folded(
        "2026-09-30-folded-authentication-results.eml",
        folds=6,
        headers={
            "authentication-results": [
                "mx.example.org;"
                f"{_TAB}spf=pass (sender IP is 192.0.2.10) smtp.mailfrom=example.net;"
                f"{_TAB}dkim=fail (signature did not verify) header.d=example.net;"
                f"{_TAB}dmarc=pass action=none header.from=example.net"
            ],
            "received-spf": [
                "Pass (mx.example.org: domain of example.net designates 192.0.2.10 as"
                " permitted sender) receiver=mx.example.org; client-ip=192.0.2.10;"
                " helo=mx.example.net;"
            ],
            "list-unsubscribe": [
                "<https://lists.example.net/unsub?id=1>, <mailto:unsub@lists.example.net>"
            ],
        },
    ),
    Folded(
        "2026-09-30-folded-nested-message.eml",
        folds=3,
        message=1,
        headers={
            "from": ["Inner Sender <inner@example.net>"],
            "subject": ["Zobacz example.com teraz"],
            "content-type": ['text/plain; charset="utf-8"'],
        },
        addresses={"from": [_address("Inner Sender", "inner@example.net")]},
    ),
)


def _not_an_address(local_part: str) -> dict[str, str | None]:
    """How an entry with no domain is reported: the quoted string is all there is."""
    return {
        "display_name": None,
        "address": f'"{local_part}"',
        "local_part": local_part,
        "domain": None,
    }


@dataclass(frozen=True)
class Quoted:
    """One saved message whose address header holds a quoted string where an address goes."""

    file: str
    header: str
    written: str
    addresses: list[dict[str, str | None]]

    @property
    def raw(self) -> bytes:
        return (REGRESSIONS / self.file).read_bytes()


# `[D25]`: an entry with no domain is read once more, and taken only when its local part is
# exactly one mailbox with a domain and the parser has nothing to say against it.
QUOTED: tuple[Quoted, ...] = (
    Quoted(
        "2026-09-30-quoted-from.eml",
        "from",
        '"Bob Example <bob@example.net>"',
        [_address("Bob Example", "bob@example.net")],
    ),
    Quoted(
        "2026-09-30-quoted-entry-in-a-list.eml",
        "to",
        'Good One <good@example.org>, "B Two <b@example.org>"',
        [_address("Good One", "good@example.org"), _address("B Two", "b@example.org")],
    ),
    Quoted(
        "2026-09-30-quoted-bare-address.eml",
        "from",
        '"bob@example.net"',
        [_address(None, "bob@example.net")],
    ),
    # Left as they were: text after the address, two addresses, no address at all. The first
    # two do hold a mailbox the parser can find, and a defect that says it is not the whole
    # of what was written.
    Quoted(
        "2026-09-30-quoted-from-with-trailing-text.eml",
        "from",
        '"Bob Example <bob@example.net> via list"',
        [_not_an_address("Bob Example <bob@example.net> via list")],
    ),
    Quoted(
        "2026-09-30-quoted-two-addresses.eml",
        "from",
        '"Bob <bob@example.net> <eve@example.org>"',
        [_not_an_address("Bob <bob@example.net> <eve@example.org>")],
    ),
    Quoted(
        "2026-09-30-quoted-name-only.eml",
        "from",
        '"Bob Example"',
        [_not_an_address("Bob Example")],
    ),
    # The control: a display name that is itself an address, in front of a real one. The
    # entry has a domain, so the rule has no business with it.
    Quoted(
        "2026-09-30-quoted-display-name-is-an-address.eml",
        "from",
        '"first@example.org" <second@example.net>',
        [_address("first@example.org", "second@example.net")],
    ),
)


@dataclass(frozen=True)
class Named:
    """One saved message whose parts carry names, and what is read out of them."""

    file: str
    # (part index, `filename`, `extension`) for every part that has a name, in order.
    names: list[tuple[int, str | None, str | None]]
    flags: list[str] = field(default_factory=list)
    # `headers{}["content-disposition"]` of the message itself, where the message is the part:
    # the parser's view `[D24]`, which `[D27]` does not bind and says where it may differ.
    disposition_view: str | None = None

    @property
    def raw(self) -> bytes:
        return (REGRESSIONS / self.file).read_bytes()


# `[D27]`: the plain form loses the white space between two adjacent encoded-words and nothing
# else; the RFC 2231 form wins wherever it stands, is read in its charset and no further, and
# gives way to the plain one, reported, when its charset is not taken; white space at the ends
# goes and a period stays.
NAMED: tuple[Named, ...] = (
    Named(
        "2026-10-03-filename-two-encoded-words.eml",
        [(2, "naïve-notes.txt", "txt"), (3, "naïve-notes.txt", "txt")],
    ),
    Named(
        "2026-10-03-filename-encoded-words-in-continuations.eml",
        [
            (2, "naïve-notes.txt", "txt"),
            (3, "naïve-notes.txt", "txt"),
            (4, "naïve-notes.txt", "txt"),
        ],
    ),
    Named(
        "2026-10-03-filename-parameter-text-after-an-encoded-word.eml",
        [
            (2, "résumé;v2.pdf", "pdf"),
            (3, "résumé;x=y.pdf", "pdf"),
            (4, "résumé;filename=other.pdf", "pdf"),
            (5, 'résumé".pdf', "pdf"),
        ],
    ),
    Named(
        "2026-10-03-filename-written-twice.eml",
        [
            (2, "résumé-one.pdf", "pdf"),
            (3, "résumé-two.pdf", "pdf"),
            (4, "résumé-three.pdf", "pdf"),
            # The control: `Content-Disposition` is read before `Content-Type`, in any form.
            (5, "disposition.pdf", "pdf"),
        ],
    ),
    Named(
        "2026-10-03-filename-charset-form-holding-an-encoded-word.eml",
        [
            (2, "=?utf-8?Q?r=C3=A9sum=C3=A9?=.pdf", "pdf"),
            (3, "naïve-=?utf-8?Q?notes?=.txt", "txt"),
        ],
    ),
    Named(
        "2026-10-03-filename-unreadable-charset-form-beside-a-plain-one.eml",
        [(2, "fallback.pdf", "pdf")],
        flags=["encoding_fallback"],
    ),
    Named(
        "2026-10-03-filename-edges.eml",
        [
            (2, "notes.pdf", "pdf"),
            (3, "résumé.pdf", "pdf"),
            (4, "archive.exe.", None),
            (5, ".profile", None),
        ],
    ),
    Named(
        "2026-10-03-filename-on-the-message-itself.eml",
        [(0, "naïve-notes.txt", "txt")],
        disposition_view='attachment; filename="naïve-no tes.txt"',
    ),
)


_FOLD = re.compile(rb"\r?\n([ \t])")
_BYTE_FACTS = {"size", "md5", "sha1", "sha256"}


def unfolded(raw: bytes) -> tuple[bytes, int]:
    """The same message with every fold taken out, and how many there were.

    RFC 5322 §2.2.3: the line break is removed and the white space after it is kept. This
    works on the whole input, so it is only a twin for a message whose body has no line
    starting with white space — which is why the count comes back with it.
    """
    return _FOLD.subn(rb"\1", raw)


def comparable(response: dict[str, Any]) -> dict[str, Any]:
    """A response without what legitimately differs between a message and its unfolded twin.

    The twin has different bytes, so everything that describes bytes goes: the sizes and
    hashes, and the identifiers, which are random anyway. Whether an artifact exists stays.
    """
    return {
        "flags": response["flags"],
        "tools": response["tools"],
        "messages": _without_byte_facts(response["messages"]),
        "artifacts": [
            {key: a[key] for key in ("kind", "message_index", "part_index", "filename", "mime")}
            for a in response["artifacts"]
        ],
    }


def _without_byte_facts(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: (item is not None) if key.endswith("artifact_id") else _without_byte_facts(item)
            for key, item in value.items()
            if key not in _BYTE_FACTS
        }
    if isinstance(value, list):
        return [_without_byte_facts(item) for item in value]
    return value


def registry_map_of_this_interpreter() -> tuple[dict[str, str], str]:
    """What the service's registry maps each header name to, here, and its default."""
    from mail_dissect.headers import _registry

    names = {name: cls.__name__ for name, cls in _registry.registry.items()}
    return names, _registry.default_class.__name__


def check_registry_map() -> None:
    names, default = registry_map_of_this_interpreter()
    assert names == REGISTRY_MAP, (
        "the header registry maps differently on this interpreter: "
        f"{sorted(set(names.items()) ^ set(REGISTRY_MAP.items()))}"
    )
    assert default == "UnstructuredHeader", default
    from mail_dissect.headers import _registry

    unstructured = {
        name for name, cls in _registry.registry.items() if issubclass(cls, UnstructuredHeader)
    }
    assert unstructured == UNSTRUCTURED, unstructured


def check_parameter_funnel() -> None:
    """`[D34]`: the bound on a part's parameters is one private method of `Message`.

    `get_param`, `get_boundary` and `get_filename` all ask `_get_params_preserve` for the
    parameters, and the service bounds that method. A Python whose readers no longer ask it
    would read every parameter of a header of any length again, so this must turn red there.
    The control is the same headers under the limit, whose parameters are read.
    """
    from email.parser import BytesParser

    from mail_dissect.headers import COMPAT32_TEXT, STRUCTURED_HEADER_LIMIT

    def parsed(length: int) -> Any:
        filler = "; x=y" * (length // 5)
        raw = (
            f'Content-Type: text/plain; charset=utf-8; boundary="BB"{filler}\r\n'
            f'Content-Disposition: attachment; filename="a.pdf"{filler}\r\n\r\nbody'
        ).encode()
        return BytesParser(policy=COMPAT32_TEXT).parsebytes(raw)

    short, long = parsed(1_000), parsed(STRUCTURED_HEADER_LIMIT)
    assert len(long["content-type"]) > STRUCTURED_HEADER_LIMIT > len(short["content-type"])
    assert (short.get_param("charset"), short.get_boundary(), short.get_filename()) == (
        "utf-8",
        "BB",
        "a.pdf",
    )
    assert (long.get_param("charset"), long.get_boundary(), long.get_filename()) == (
        None,
        None,
        None,
    )


def check_values(case: Folded, dissect: Dissect) -> None:
    """The folded message yields the values its headers hold, not the lines they were on."""
    message = dissect(case.raw)["messages"][case.message]
    for name, expected in case.headers.items():
        assert message["headers"].get(name) == expected, (case.file, name)
    for name, expected_addresses in case.addresses.items():
        assert message["addresses"].get(name) == expected_addresses, (case.file, name)


def check_twin(case: Folded, dissect: Dissect) -> None:
    """The folded message and its unfolded twin are the same message to a consumer."""
    twin, removed = unfolded(case.raw)
    assert removed == case.folds, f"{case.file}: removed {removed} folds, expected {case.folds}"
    assert twin != case.raw
    assert comparable(dissect(case.raw)) == comparable(dissect(twin)), case.file


def check_quoted(case: Quoted, dissect: Dissect) -> None:
    """The entry is the address written inside the quotes, or it is left exactly as it was."""
    message = dissect(case.raw)["messages"][0]
    assert message["addresses"][case.header] == case.addresses, case.file
    # The view of the header itself does not move: it still shows what was written.
    assert message["headers"][case.header] == [case.written], case.file


def check_named(case: Named, dissect: Dissect) -> None:
    """Every place the service shows a part's name shows the one reading of it."""
    body = dissect(case.raw)
    message = body["messages"][0]
    attachments = {item["part_index"]: item for item in message["attachments"]}
    for index, filename, extension in case.names:
        got = message["mime_parts"][index]["filename"]
        assert got == filename, (case.file, index, got)
        assert attachments[index]["filename"] == filename, (case.file, index)
        assert attachments[index]["extension"] == extension, (case.file, index)
    assert body["flags"] == case.flags, (case.file, body["flags"])
    if case.disposition_view is not None:
        view = message["headers"]["content-disposition"]
        assert view == [case.disposition_view], (case.file, view)


def main() -> int:
    from fastapi.testclient import TestClient

    from mail_dissect.app import create_app
    from mail_dissect.settings import Settings

    failures = 0
    ran = 0
    with tempfile.TemporaryDirectory() as directory:
        settings = Settings(_env_file=None, artifact_dir=directory)  # type: ignore[call-arg]
        with TestClient(create_app(settings)) as client:

            def dissect(raw: bytes) -> dict[str, Any]:
                response = client.post(
                    "/v1/dissect", content=raw, headers={"content-type": "message/rfc822"}
                )
                assert response.status_code == 200, response.text
                body: dict[str, Any] = response.json()
                return body

            checks: list[tuple[str, Callable[[], None]]] = [
                ("registry map", check_registry_map),
                ("parameter funnel", check_parameter_funnel),
            ]
            for case in FOLDED:
                checks.append((f"values {case.file}", lambda c=case: check_values(c, dissect)))
                checks.append((f"twin   {case.file}", lambda c=case: check_twin(c, dissect)))
            for quoted in QUOTED:
                checks.append((f"quoted {quoted.file}", lambda q=quoted: check_quoted(q, dissect)))
            for named in NAMED:
                checks.append((f"named  {named.file}", lambda n=named: check_named(n, dissect)))
            for label, check in checks:
                ran += 1
                try:
                    check()
                except AssertionError as error:
                    failures += 1
                    print(f"FAIL {label}: {error}")
    print(f"python {sys.version.split()[0]}: {ran} pins checked, {failures} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
