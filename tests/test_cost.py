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
