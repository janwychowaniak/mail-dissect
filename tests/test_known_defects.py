"""Known defects: what `CHANGELOG.md` lists under that heading, one saved message each.

A defect that is known and not yet fixed is stated here as the contract states it, and marked
as an expected failure — strictly, so the day it is fixed the test fails until the mark and
the entry in `CHANGELOG.md` are removed. An entry cannot outlive its defect, and a defect
cannot be forgotten by being fixed in passing.

An expected failure is satisfied by any failure, which is the trap of this file: a broken
fixture would keep it green for ever. So each defect comes with a control that is an ordinary
test — the same material, one step away from the defect, where the service does what the
contract says — and the mark accepts an `AssertionError` and nothing else.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import dissect
from fastapi.testclient import TestClient

REGRESSIONS = Path(__file__).parent / "regressions"

# SPEC §11.3: a defanged form is re-armed and marked. Each line of the saved message is one
# form, written directly after a hyphen or a period.
DEFANGED_AFTER_A_MARK = REGRESSIONS / "2026-10-01-defanged-after-a-hyphen-or-a-period.eml"
RE_ARMED = [
    ("domain", "one.example.net", "one[.]example[.]net"),
    ("url", "http://two.example.net/path", "hxxp://two[.]example[.]net/path"),
    ("domain", "two.example.net", "hxxp://two[.]example[.]net/path"),
    ("email", "user@three.example.net", "user[at]three[.]example[.]net"),
    ("domain", "three.example.net", "user[at]three[.]example[.]net"),
    ("ip", "192.0.2.201", "192[.]0[.]2[.]201"),
    ("domain", "four.example.net", "four[.]example[.]net"),
]


def _defanged(client: TestClient, raw: bytes) -> list[tuple[str, str, str]]:
    found = dissect(client, raw)["messages"][0]["observables"]
    return [(o["type"], o["value"], o["value_raw"]) for o in found if o["defanged"]]


def test_the_defanged_forms_are_returned_after_a_space(client: TestClient) -> None:
    """The control: the saved message with a space put after each leading hyphen or period."""
    raw = DEFANGED_AFTER_A_MARK.read_bytes()
    assert raw.count(b"\r\n-") == 4 and raw.count(b"\r\n.") == 1
    spaced = raw.replace(b"\r\n-", b"\r\n- ").replace(b"\r\n.", b"\r\n. ")
    assert _defanged(client, spaced) == RE_ARMED


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="known defect, listed in CHANGELOG.md: a defanged form directly after a hyphen or "
    "a period is not returned",
)
def test_a_defanged_form_directly_after_a_hyphen_or_a_period(client: TestClient) -> None:
    """The marker is grown outwards to its token, and the mark in front is taken along."""
    assert _defanged(client, DEFANGED_AFTER_A_MARK.read_bytes()) == RE_ARMED
