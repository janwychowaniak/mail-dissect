"""What the scan costs on the inputs found worst: SPEC §15, F22.

Each case is an absolute threshold far from both paths: the input is long enough that the old,
quadratic cost is minutes, and the linear one a fraction of a second. A relative threshold,
such as "the defanged spelling costs at most k times the plain one", would pass with both
paths quadratic, so none is used. The units are the worst the sweep in
`docs/research/probes/grammar.py` found on 0.6.0, and the sweep is what finds the next one:
these are chosen, it searches.
"""

from __future__ import annotations

import time

import builders as b
import pytest
from conftest import dissect
from fastapi.testclient import TestClient

pytestmark = pytest.mark.cost

LENGTH = 100_000
THRESHOLD = 5.0

# Units where an address or a URL with a scheme may start at every word boundary of the run
# and read to its end before failing: the characters of a local part, of a scheme, and the
# colon that ends a scheme with nothing after it that completes one.
RUN_STARTS = ["a-", "-a", "a/", "=a", "*1", "a+", "a:", "a.a:"]


@pytest.mark.parametrize("unit", RUN_STARTS)
def test_a_run_where_a_candidate_may_start_anywhere_is_read_in_linear_time(
    client: TestClient, unit: str
) -> None:
    """F22: on 0.6.0 each of these took about half a second for 4,000 characters, growing
    as the square of the length; here the run is 100,000 characters.

    The run is under `MAX_RUN_LENGTH`, so it is read rather than skipped, and the response
    says nothing was cut: a fast answer from a run the scan never saw would prove nothing.
    """
    text = (unit * (LENGTH // len(unit) + 1))[:LENGTH]
    raw = b.message({"Subject": "s"}, body=text.encode())

    started = time.perf_counter()
    body = dissect(client, raw)
    elapsed = time.perf_counter() - started

    assert body["flags"] == []
    assert elapsed < THRESHOLD, f"{unit!r}: took {elapsed:.1f}s for {LENGTH} characters"


URL = "http://a.example.net/x"


def _timed(client: TestClient, raw: bytes) -> tuple[dict, float]:
    started = time.perf_counter()
    body = dissect(client, raw)
    return body, time.perf_counter() - started


def test_a_run_of_markers_is_read_in_linear_time(client: TestClient) -> None:
    """F22: each marker was grown outwards to its token, so 200,000 characters of `a[.]` took
    about 30 seconds on 0.6.0. They are re-armed once now `[D28]`, and read like `a.a.a`.

    The run is under `MAX_RUN_LENGTH`, and the defanged form after it comes back, so the
    markers reached the scan."""
    run = "a[.]" * 50_000
    assert len(run) < 262_144
    raw = b.message({"Subject": "s"}, body=f"{run} one[.]example[.]net".encode())

    body, elapsed = _timed(client, raw)

    assert body["flags"] == []
    found = [(o["value"], o["defanged"]) for o in body["messages"][0]["observables"]]
    assert found == [("one.example.net", True)]
    assert elapsed < THRESHOLD, f"took {elapsed:.1f}s"


def test_cid_references_are_pointed_at_their_assets_in_one_pass() -> None:
    """F29: each part's reference was a replace over the whole HTML, so the cost was the HTML's
    length times the number of parts, about 23 seconds for 45 MB and 500 parts, the largest
    message and the most parts the service takes. One pass reads the HTML once `[D38]`, and
    every reference is still rewritten."""
    from mail_dissect.dissect import _point_at_assets

    names = {f"img{i}@example.net": f"cid-{i}.png" for i in range(500)}
    references = "".join(f'<img src="cid:img{i}@example.net">' for i in range(500))
    filler = "<p>" + "Dear customer, your order has shipped. " * 50 + "</p>\n"
    html = references + filler * (45_000_000 // len(filler))

    started = time.perf_counter()
    rewritten = _point_at_assets(html, names)
    elapsed = time.perf_counter() - started

    assert rewritten.count('src="cid-') == 500 and "cid:" not in rewritten
    assert elapsed < THRESHOLD, f"took {elapsed:.1f}s"


def test_a_long_tail_of_closers_is_trimmed_in_linear_time(client: TestClient) -> None:
    """F22: trimming took a character off at a time, copying the rest and counting the
    brackets again, so a URL followed by 192,000 `}` took about 53 seconds. Here the tail is
    200,000 long, and the URL comes back without it."""
    raw = b.message({"Subject": "s"}, body=f"see {URL}{'}' * 200_000} now".encode())

    body, elapsed = _timed(client, raw)

    assert [o["value"] for o in body["messages"][0]["observables"]][:2] == [URL, "a.example.net"]
    assert elapsed < THRESHOLD, f"took {elapsed:.1f}s"


def test_long_tails_of_periods_are_trimmed_in_linear_time(client: TestClient) -> None:
    """A period is cheaper to cut than a closer, so one tail within `MAX_RUN_LENGTH` cost
    about a second the old way (192,000 periods, F22): eight of them, each as long as a run may
    be, are what puts the old cost far above the threshold and the new one far below it."""
    tail = "." * (250_000 - len(URL))
    text = " ".join(f"{URL}{tail}" for _ in range(8))
    raw = b.message({"Subject": "s"}, body=text.encode())

    body, elapsed = _timed(client, raw)

    assert body["flags"] == []
    assert body["messages"][0]["observables"][0] == {
        **body["messages"][0]["observables"][0],
        "value": URL,
        "occurrences": 8,
    }
    assert elapsed < THRESHOLD, f"took {elapsed:.1f}s"


def test_css_addresses_are_read_in_linear_time(client: TestClient) -> None:
    """F22: the unquoted branch of `url(` ran to the end of the run at every `url(` and failed
    there; 16,000 characters of them took 1.3 seconds, growing as the square."""
    css = "url(" * 25_000
    raw = b.message(
        {"Subject": "s", "Content-Type": "text/html"},
        body=f"<style>{css}</style><p>after.example.net</p>".encode(),
    )

    body, elapsed = _timed(client, raw)

    assert "after.example.net" in [o["value"] for o in body["messages"][0]["observables"]]
    assert elapsed < THRESHOLD, f"took {elapsed:.1f}s"


def test_a_received_field_of_open_comments_is_read_in_linear_time() -> None:
    """F22: the comment branch read to the end of the field at every keyword when no `)` was
    left; 128,000 characters of `from a (` took 2.5 seconds, growing as the square."""
    from mail_dissect.headers import parse_received

    started = time.perf_counter()
    hop = parse_received("from a (" * 64_000 + "; Sun, 4 Oct 2026 10:00:00 +0000")
    elapsed = time.perf_counter() - started

    assert hop.from_host == "a"
    assert elapsed < THRESHOLD, f"took {elapsed:.1f}s"


def test_an_authentication_result_with_a_long_run_is_read_in_linear_time() -> None:
    """F22: a parameter name was tried from every character of a run with no `=` after it;
    32,000 such characters took 17 seconds."""
    from mail_dissect.headers import parse_auth_results

    started = time.perf_counter()
    results = parse_auth_results("mx.example.net; spf=pass " + "a" * 64_000 + " smtp.mailfrom=x")
    elapsed = time.perf_counter() - started

    assert results[0].params == {"smtp.mailfrom": "x"}
    assert elapsed < THRESHOLD, f"took {elapsed:.1f}s"


def test_one_value_in_many_places_is_counted_in_linear_time() -> None:
    """F22: whether a place was already listed was a search of the list, so one value in
    20,000 places took 42 seconds."""
    from mail_dissect.observables import Collector, Source
    from mail_dissect.registries import Registries

    collector = Collector(Registries.load())
    started = time.perf_counter()
    for index in range(30_000):
        collector.feed_text("host.example.net", Source("header", "x-a", index))
    elapsed = time.perf_counter() - started

    (candidate,) = collector.finish()
    assert candidate.occurrences == 30_000 and len(candidate.sources) == 30_000
    assert elapsed < THRESHOLD, f"took {elapsed:.1f}s"


def test_a_long_tail_of_parentheses_is_trimmed_in_linear_time(client: TestClient) -> None:
    """A `)` may stand in a path since `[D31]`, so a tail of them is now part of the match and
    is trimmed off, as a tail of `}` was. The head `(y)` is the control: it shows the tail went
    through the grammar and the trimming, since 0.6.0 returned `…/x(y` and a fast answer that
    cut the URL short would prove nothing."""
    raw = b.message({"Subject": "s"}, body=f"see {URL}(y){')' * 200_000} now".encode())

    body, elapsed = _timed(client, raw)

    assert body["messages"][0]["observables"][0]["value"] == f"{URL}(y)"
    assert elapsed < THRESHOLD, f"took {elapsed:.1f}s"


def test_long_tails_of_commas_are_trimmed_in_linear_time(client: TestClient) -> None:
    """A comma may stand in a path since `[D31]`; its tail is cheap to cut, like a period's, so
    eight of them as long as a run may be. The head `,y` is the control, as `(y)` is above."""
    tail = "," * (250_000 - len(URL) - 2)
    text = " ".join(f"{URL},y{tail}" for _ in range(8))
    raw = b.message({"Subject": "s"}, body=text.encode())

    body, elapsed = _timed(client, raw)

    first = body["messages"][0]["observables"][0]
    assert (first["value"], first["occurrences"]) == (f"{URL},y", 8)
    assert elapsed < THRESHOLD, f"took {elapsed:.1f}s"


def test_a_structured_header_past_its_limit_is_not_parsed(client: TestClient) -> None:
    """F24: the header parser costs its steps times what is left to read. One `Cc` of 40,000
    periods took minutes, and a `Content-Type` of 8,000 `(a)` sixteen seconds; past the
    structured limit neither is parsed `[D33]`, and their bodies are still read."""
    raw = b.message(
        # A `Content-Type` with no type in it is `text/plain` to the parser, so the body is
        # still the text body, read after the header that is not.
        {"Cc": "." * 40_000, "Content-Type": "(a)" * 8_000},
        body=b"body mentions body.example.net",
    )

    body, elapsed = _timed(client, raw)

    assert "body.example.net" in [o["value"] for o in body["messages"][0]["observables"]]
    assert elapsed < THRESHOLD, f"took {elapsed:.1f}s"


def test_a_million_parameters_are_not_split(client: TestClient) -> None:
    """F25: splitting a part header's parameters costs seven microseconds each, so a million
    `;` took seven seconds, and a boundary search over them three more. Past the structured
    limit they are not split `[D34]`."""
    raw = b.message(
        {"Content-Type": "multipart/mixed" + ";" * 1_000_000}, body=b"--x\r\n\r\npart\r\n--x--\r\n"
    )

    body, elapsed = _timed(client, raw)

    assert [part["content_type"] for part in body["messages"][0]["mime_parts"]] == [
        "multipart/mixed"
    ]
    assert elapsed < THRESHOLD, f"took {elapsed:.1f}s"


def test_a_nested_message_written_out_again_is_not_refolded(client: TestClient) -> None:
    """`[D35]`: writing a nested message out again refolded every header line over 78
    characters through the header registry, so a `Cc` of 16,000 periods inside it took five and
    a half seconds there, growing as the square (F26). It is written as stored now. The
    delimiters end in a bare CR, which is what sends the nested message down this path."""
    raw = (
        b'From: a@example.net\nContent-Type: multipart/mixed; boundary="b"\n\n'
        b"--b\rContent-Type: text/plain\n\nouter\n"
        b"--b\rContent-Type: message/rfc822\n\nFrom: c@example.net\nCc: "
        + b"."
        * 32_000
        + b'\nContent-Type: multipart/alternative; boundary="c"\n\n'
        b"--c\nContent-Type: text/plain\n\ninner\n--c--\n--b--\r"
    )

    body, elapsed = _timed(client, raw)

    assert len(body["messages"]) == 2 and "malformed_mime" in body["flags"]
    assert elapsed < THRESHOLD, f"took {elapsed:.1f}s"
