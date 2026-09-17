"""HTML: links, resources, derived text and unwrappers.

SPEC §9, §10. Acceptance cases 5, 6, 7, 21, 22, 23, 38, 40, 41, 49, 50, 60.
"""

from __future__ import annotations

import base64
import quopri
from urllib.parse import quote

import builders as b
import pytest
from conftest import FakeClock, dissect
from fastapi.testclient import TestClient

from mail_dissect.app import create_app
from mail_dissect.settings import Settings

SAFELINKS = {"host_suffix": "safelinks.example", "source": "query:url", "decoder": "percent"}
GATEWAY = {"host_suffix": "wrap.example", "source": "path_segment:1", "decoder": "base64url"}


def _html_message(html: str, **parts: bytes) -> bytes:
    pieces = [b.part("text/html", html.encode())]
    pieces.extend(parts.values())
    return b.multipart("mixed", *pieces)


def _with_unwrappers(settings: Settings, clock: FakeClock, *rules: dict) -> TestClient:
    # Through the constructor, not model_copy: `update=` assigns without validating, so the
    # rules would arrive as plain dicts - which is not what the environment ever produces.
    configured = Settings(**{**settings.model_dump(), "unwrappers": list(rules)}, _env_file=None)
    return TestClient(create_app(configured, clock=clock))


def test_long_url_broken_by_quoted_printable_is_recovered_whole(client: TestClient) -> None:
    """Test 5: the address must be read from DECODED content, never from raw bytes.

    An implementation that scans the raw message passes with the URL cut in half, and the
    result still looks like a URL — so the assertion compares the whole value, not the shape.
    """
    target = "https://example.com/" + "segment/" * 20 + "?token=" + "a" * 60
    html = f'<a href="{target}">click</a>'
    encoded = quopri.encodestring(html.encode())
    assert b"=\n" in encoded, "the fixture must actually be folded, or it proves nothing"

    raw = b.multipart("mixed", b.part("text/html", html.encode(), encoding="quoted-printable"))
    links = dissect(client, raw)["messages"][0]["links"]
    assert [link["href"] for link in links] == [target]


def test_reversible_wrapper(settings: Settings, clock: FakeClock) -> None:
    """Test 6: `href` is the target, `rewritten_from` is what stood in the message."""
    target = "https://real.example/landing?id=7"
    wrapped = f"https://eu01.safelinks.example/?url={quote(target, safe='')}"
    with _with_unwrappers(settings, clock, SAFELINKS) as client:
        link = dissect(client, _html_message(f'<a href="{wrapped}">go</a>'))["messages"][0][
            "links"
        ][0]
    assert link["href"] == target
    assert link["rewritten_from"] == wrapped
    assert link["host"] == "real.example"  # the decomposition describes the target
    assert link["unwrap_failed"] is False


def test_wrapper_outside_the_table_passes_through(settings: Settings, clock: FakeClock) -> None:
    """Test 7: reversibility is the result of trying, and we never try over the network.

    The autouse socket guard is the second half of this assertion: a wrapper we cannot
    unwrap must not tempt anyone into resolving it.
    """
    wrapped = "https://unknown-gateway.example/?u=aHR0cHM6Ly9yZWFsLmV4YW1wbGU="
    with _with_unwrappers(settings, clock, SAFELINKS) as client:
        link = dissect(client, _html_message(f'<a href="{wrapped}">go</a>'))["messages"][0][
            "links"
        ][0]
    assert link["href"] == wrapped
    assert link["rewritten_from"] is None
    assert link["unwrap_failed"] is False  # nothing was attempted, so nothing failed


def test_wrapper_inside_a_wrapper(settings: Settings, clock: FakeClock) -> None:
    """Test 40: to a fixed point, with the OUTERMOST address in `rewritten_from`."""
    target = "https://real.example/landing"
    inner = f"https://eu01.safelinks.example/?url={quote(target, safe='')}"
    encoded = base64.urlsafe_b64encode(inner.encode()).decode().rstrip("=")
    outer = f"https://gw2.wrap.example/r/{encoded}"
    with _with_unwrappers(settings, clock, SAFELINKS, GATEWAY) as client:
        link = dissect(client, _html_message(f'<a href="{outer}">go</a>'))["messages"][0]["links"][
            0
        ]
    assert link["href"] == target
    assert link["rewritten_from"] == outer, "not the intermediate form"


def test_matching_entry_that_cannot_unwrap(settings: Settings, clock: FakeClock) -> None:
    """Test 41: "we tried and failed" must not look like "there was nothing to unwrap"."""
    missing_parameter = "https://eu01.safelinks.example/?other=1"
    broken_encoding = "https://gw2.wrap.example/r/!!!not-base64!!!"
    with _with_unwrappers(settings, clock, SAFELINKS, GATEWAY) as client:
        body = dissect(
            client,
            _html_message(f'<a href="{missing_parameter}">a</a><a href="{broken_encoding}">b</a>'),
        )
    for link in body["messages"][0]["links"]:
        assert link["rewritten_from"] is None
        assert link["unwrap_failed"] is True
    assert body["messages"][0]["links"][0]["href"] == missing_parameter


def test_rewritten_resource(settings: Settings, clock: FakeClock) -> None:
    """Test 60 `[D2]`: unwrapping applies to resources too, failure included."""
    target = "https://real.example/pixel.gif"
    wrapped = f"https://eu01.safelinks.example/?url={quote(target, safe='')}"
    broken = "https://eu01.safelinks.example/?nothing=here"
    with _with_unwrappers(settings, clock, SAFELINKS) as client:
        resources = dissect(client, _html_message(f'<img src="{wrapped}"><img src="{broken}">'))[
            "messages"
        ][0]["resources"]
    assert resources[0]["href"] == target
    assert resources[0]["rewritten_from"] == wrapped
    assert resources[0]["host"] == "real.example"
    assert resources[1]["unwrap_failed"] is True
    assert resources[1]["href"] == broken


def test_mailto_anchor_and_cid_resource(client: TestClient) -> None:
    """Test 21: no filtering by scheme, and `cid:` points at a part of this message."""
    html = '<a href="mailto:sales@example.com">mail</a><img src="cid:logo001">'
    raw = b.multipart(
        "related",
        b.part("text/html", html.encode()),
        b.part(
            "image/png",
            b"\x89PNG\r\n\x1a\n",
            content_id="<logo001>",
            disposition="inline",
            filename="logo.png",
        ),
    )
    message = dissect(client, raw)["messages"][0]
    link = message["links"][0]
    assert link["scheme"] == "mailto" and link["host"] is None
    assert link["path"] == "sales@example.com"
    resource = message["resources"][0]
    assert resource["scheme"] == "cid" and resource["host"] is None
    assert resource["cid_part"] == 2
    assert message["mime_parts"][2]["content_id"] == "<logo001>"


def test_url_with_userinfo(client: TestClient) -> None:
    """Test 23: the decomposition is not fooled by the `@` substitution."""
    link = dissect(client, _html_message('<a href="https://bank.example@zly.host/">x</a>'))[
        "messages"
    ][0]["links"][0]
    assert link["host"] == "zly.host"
    assert link["userinfo"] == "bank.example"


def test_relative_address_enters_as_it_is(client: TestClient) -> None:
    """SPEC §9.1: useless in a mail message, but its presence is a fact about the content."""
    link = dissect(client, _html_message('<a href="/local/path">x</a>'))["messages"][0]["links"][0]
    assert link["href"] == "/local/path"
    assert link["scheme"] is None and link["host"] is None


def test_same_address_as_anchor_and_as_resource(client: TestClient) -> None:
    """Test 22 (HTML half): two different events in the recipient's client, both reported."""
    address = "https://tracker.example/pixel.gif"
    message = dissect(client, _html_message(f'<img src="{address}"><a href="{address}">same</a>'))[
        "messages"
    ][0]
    assert [r["href"] for r in message["resources"]] == [address]
    assert [link["href"] for link in message["links"]] == [address]


def test_related_with_alternative_inside(client: TestClient) -> None:
    """Test 38: the body comes out of the `alternative`, the image is an inline attachment."""
    raw = b.multipart(
        "related",
        b.multipart(
            "alternative",
            b.part("text/plain", b"plain body"),
            b.part("text/html", b'<p>html body <a href="cid:logo001">logo</a></p>'),
            boundary="ALT",
        ),
        b.part(
            "image/png",
            b"\x89PNG\r\n\x1a\n",
            content_id="<logo001>",
            disposition="inline",
            filename="logo.png",
        ),
        boundary="REL",
    )
    message = dissect(client, raw)["messages"][0]
    assert message["body"]["text"] == "plain body"
    assert message["body"]["html"].startswith("<p>html body")
    attachment = message["attachments"][0]
    assert attachment["disposition"] == "inline"
    assert attachment["content_id"] == "<logo001>"
    assert message["links"][0]["cid_part"] == attachment["part_index"]


def test_text_from_html(client: TestClient) -> None:
    """Test 49: it does not replace `body.text`, and it is there when there is none."""
    html = b"<div>Hello <b>world</b></div><p>Second&nbsp;line</p>"
    only_html = dissect(client, b.multipart("mixed", b.part("text/html", html)))["messages"][0]
    assert only_html["body"]["text"] is None
    assert only_html["body"]["text_from_html"] == "Hello world\n\nSecond line"

    with_plain = b.multipart(
        "alternative", b.part("text/plain", b"the plain part"), b.part("text/html", html)
    )
    both = dissect(client, with_plain)["messages"][0]
    assert both["body"]["text"] == "the plain part"
    assert both["body"]["text_from_html"] == "Hello world\n\nSecond line"
    assert both["body"]["text"] != both["body"]["text_from_html"]


def test_attributes_are_never_text(client: TestClient) -> None:
    """SPEC §9.3 rule 3, which is the same structural rule as §9.2."""
    html = b'<img src="http://x.example/i.png" alt="ALTTEXT" title="TITLETEXT">visible'
    message = dissect(client, b.multipart("mixed", b.part("text/html", html)))["messages"][0]
    assert message["body"]["text_from_html"] == "visible"


def test_namespace_declarations_are_not_addresses(client: TestClient) -> None:
    """SPEC §9.2: not an exclusion list — the attribute is simply never read."""
    html = b'<svg xmlns="http://www.w3.org/2000/svg"><use href="#icon"/></svg>plain'
    message = dissect(client, b.multipart("mixed", b.part("text/html", html)))["messages"][0]
    assert all("w3.org" not in (r["href"] or "") for r in message["resources"])
    assert all("w3.org" not in (link["href"] or "") for link in message["links"])


@pytest.mark.parametrize("field", ["html", "text_from_html"])
def test_inline_threshold_per_representation(
    settings: Settings, clock: FakeClock, field: str
) -> None:
    """Test 50 `[D4]`: each representation has its own threshold and its own link."""
    html = b"<p>" + b"x" * 5000 + b"</p>"
    raw = b.multipart("mixed", b.part("text/html", html))

    below = settings.model_copy(update={"max_inline_body_bytes": 100_000})
    with TestClient(create_app(below, clock=clock)) as client:
        body = dissect(client, raw)["messages"][0]["body"]
    assert body[field] is not None
    assert body[f"{field}_artifact_id"] is not None

    above = settings.model_copy(update={"max_inline_body_bytes": 100})
    with TestClient(create_app(above, clock=clock)) as client:
        answer = dissect(client, raw)
    body = answer["messages"][0]["body"]
    assert body[field] is None, "above the threshold the content lives only in the artifact"
    artifact_id = body[f"{field}_artifact_id"]
    assert artifact_id is not None, "the link is filled regardless of the threshold"

    fetched = client.get(f"/v1/artifact/{answer['dissect_id']}/{artifact_id}")
    assert fetched.status_code == 200 and len(fetched.content) > 100
