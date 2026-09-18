"""Resilience: damage a correct message and require the service not to fall over.

SPEC §18. The criterion is single and hard — no unhandled exception and no run past the time
limit — and the acceptable answers are a correct response, however poor, or an error envelope
with a code from §16. Never a 500.

The default run is short and uses fixed seeds, so it is deterministic and belongs in CI. The
long run is behind the `fuzz` marker and takes its seed from the environment:

    MAIL_DISSECT_FUZZ_SEED=$RANDOM uv run pytest -q -m fuzz
"""

from __future__ import annotations

import os
import random
import time
from pathlib import Path

import builders as b
import mutate
import pytest
from conftest import dissect
from fastapi.testclient import TestClient

from mail_dissect.models import DissectResponse

ACCEPTABLE_STATUS = {200, 400, 413, 422}
REGRESSIONS = Path(__file__).parent / "regressions"

DEFAULT_SEEDS = (1, 7, 42, 1337)
DEFAULT_ROUNDS = 60
LONG_ROUNDS = 400


def _corpus() -> list[bytes]:
    """Correct messages to damage — one of every shape the parser has a path for."""
    inner = b.message({"From": "inner@example.net", "Subject": "forwarded"}, body=b"inner")
    return [
        b.simple_text("plain body with https://example.net/a and 10.0.0.1"),
        b.multipart(
            "alternative",
            b.part("text/plain", b"plain"),
            b.part("text/html", b'<p><a href="https://example.net/x">link</a></p>'),
        ),
        b.multipart(
            "mixed",
            b.part("text/plain", b"body", charset="utf-8"),
            b.part("application/pdf", b"%PDF-1.4 data", encoding="base64", filename="a.pdf"),
            b.nested(inner),
        ),
        b.multipart("mixed", b.nested(inner, encoding="base64")),
    ]


def _check(client: TestClient, raw: bytes, label: str, budget: float) -> None:
    """One damaged message: it may be refused, it may be poor, it may not be a 500."""
    started = time.perf_counter()
    response = client.post("/v1/dissect", content=raw, headers={"content-type": "message/rfc822"})
    elapsed = time.perf_counter() - started

    assert response.status_code in ACCEPTABLE_STATUS, f"{label}: status {response.status_code}"
    body = response.json()
    if response.status_code == 200:
        assert body["ok"] is True
        # Re-validating through the response model is what catches a shape that only looks
        # right: the model is the same one production serialises with.
        DissectResponse.model_validate(body)
    else:
        assert body["ok"] is False
        assert body["error"]["code"] != "INTERNAL", f"{label}: {body['error']}"
        assert body["dissect_id"]
    assert elapsed < budget, f"{label}: took {elapsed:.1f}s"


@pytest.mark.parametrize("seed", DEFAULT_SEEDS)
def test_mutations_do_not_topple_the_service(client: TestClient, seed: int) -> None:
    """The short, deterministic run. Fixed seeds so CI fails for a reason, not by luck."""
    rng = random.Random(seed)
    corpus = _corpus()
    for round_number in range(DEFAULT_ROUNDS):
        original = rng.choice(corpus)
        name, damaged = mutate.mutate(original, rng)
        _check(client, damaged, f"seed={seed} round={round_number} mutation={name}", 30.0)


@pytest.mark.fuzz
def test_the_long_run(client: TestClient) -> None:
    """The long run, with a seed that is reported so any finding can be reproduced.

    A finding does not end its life as a seed number: save the bytes into `regressions/` and
    it is replayed forever after `[D18]`.
    """
    seed = int(os.environ.get("MAIL_DISSECT_FUZZ_SEED", random.randrange(2**32)))
    print(f"\nfuzz seed: {seed}  (MAIL_DISSECT_FUZZ_SEED={seed} to reproduce)")
    rng = random.Random(seed)
    corpus = _corpus()
    for round_number in range(LONG_ROUNDS):
        original = rng.choice(corpus)
        name, damaged = mutate.mutate(original, rng)
        _check(client, damaged, f"seed={seed} round={round_number} mutation={name}", 30.0)


@pytest.mark.parametrize("path", sorted(REGRESSIONS.glob("*.eml")), ids=lambda p: p.name)
def test_saved_findings_stay_fixed(client: TestClient, path: Path) -> None:
    """Every input that ever broke the parser, replayed `[D18]`."""
    _check(client, path.read_bytes(), path.name, 30.0)


def test_a_message_that_is_not_one_is_refused(client: TestClient) -> None:
    """The boundary the fuzzer leans on: below it, refusal; above it, flags."""
    response = client.post(
        "/v1/dissect",
        content=b"\x00\x01\x02 no headers here",
        headers={"content-type": "message/rfc822"},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "UNPARSABLE"


def test_damage_is_reported_rather_than_hidden(client: TestClient) -> None:
    """A mutation that survives must still say what happened to it."""
    raw = mutate.remove_closing_boundary(
        b.multipart("mixed", b.part("text/plain", b"body")), random.Random(0)
    )
    body = dissect(client, raw)
    assert "malformed_mime" in body["flags"]
