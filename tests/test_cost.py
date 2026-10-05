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
