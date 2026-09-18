"""The overriding criterion (SPEC §17).

The same message, the same limits, the same registry versions: the same result, array order
included. What is excluded is the *composition* of what depends on the environment — the
random identifiers, the tool states, what the tools produce — and never the ORDER of anything.
"""

from __future__ import annotations

import json
from pathlib import Path

import builders as b
import pytest
from conftest import mask_environment
from fastapi.testclient import TestClient

GOLDEN = Path(__file__).parent / "golden" / "observables.json"


def _sample_messages() -> dict[str, bytes]:
    """One of every shape that feeds the collector, so ordering has somewhere to go wrong."""
    inner = b.message(
        {"From": "inner@example.net", "Subject": "https://from-nested.example/x"},
        body=b"nested body with nested.example.net and 10.1.2.3",
    )
    return {
        "headers_text_html": b.multipart(
            "alternative",
            b.part("text/plain", b"plain: bit.ly/xyz and sales@example.net"),
            b.part(
                "text/html",
                b'<p>html: <a href="https://anchor.example/a">x</a>'
                b'<img src="https://resource.example/p.gif"></p>',
            ),
            headers={
                "From": "Sender <sender@example.net>",
                "X-Origin": "https://header.example/one",
                "X-Origin-Two": "10.0.0.5 and raport.zip",
            },
        ),
        "defanged_and_repeated": b.message(
            {"Subject": "a plain subject"},
            body=(
                b"hxxp://zly[.]host twice: hxxp://zly[.]host\n"
                b"a(at)b[.]com and README.md and wersja.1.2\n"
                b"d41d8cd98f00b204e9800998ecf8427e and 2001:db8::1\n"
            ),
        ),
        "nested": b.multipart(
            "mixed", b.part("text/plain", b"cover: cover.example.net"), b.nested(inner)
        ),
    }


def _dissect(client: TestClient, raw: bytes) -> dict:
    response = client.post("/v1/dissect", content=raw, headers={"content-type": "message/rfc822"})
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.parametrize("name", sorted(_sample_messages()))
def test_the_same_message_twice(client: TestClient, name: str) -> None:
    """Deep equality, array order included, after masking what §17 excludes."""
    raw = _sample_messages()[name]
    first = mask_environment(_dissect(client, raw))
    second = mask_environment(_dissect(client, raw))
    assert first == second


@pytest.mark.parametrize("name", sorted(_sample_messages()))
def test_both_channels_agree(client: TestClient, name: str) -> None:
    raw = _sample_messages()[name]
    through_body = mask_environment(_dissect(client, raw))
    form = client.post("/v1/dissect", files={"eml": ("m.eml", raw, "message/rfc822")})
    assert form.status_code == 200
    assert mask_environment(form.json()) == through_body


def test_golden_observables(client: TestClient) -> None:
    """A checked-in table of what each sample yields, in order.

    Deep equality between two runs of the same process cannot notice a reordering that is
    stable — both runs would agree on the wrong order. This table is what catches that, and
    it is written by hand-review rather than by whatever the code did last.
    """
    expected = json.loads(GOLDEN.read_text(encoding="utf-8"))
    actual = {
        name: [
            [o["type"], o["value"], o["occurrences"], o["sources"][0]["kind"]]
            for o in _dissect(client, raw)["messages"][0]["observables"]
        ]
        for name, raw in _sample_messages().items()
    }
    assert actual == expected
