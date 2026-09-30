"""What the service reads out of a header, pinned to the interpreter that does the reading.

`headers{}` and `addresses{}` are the standard library's header parser at work `[D24]`, and
that parser moves between patch releases of Python. So these expectations have two homes: the
suite runs them on the developer's interpreter, and CI runs this file inside the built image,
on the interpreter that is actually published:

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

            checks: list[tuple[str, Callable[[], None]]] = [("registry map", check_registry_map)]
            for case in FOLDED:
                checks.append((f"values {case.file}", lambda c=case: check_values(c, dissect)))
                checks.append((f"twin   {case.file}", lambda c=case: check_twin(c, dissect)))
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
