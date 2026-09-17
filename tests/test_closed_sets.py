"""The closed value sets in the code must match the ones in the specification (SPEC §5.1).

Widening one of them is a `/v2` change, not an edit. Nothing but a test keeps the models and
the document in step, because both are plausible on their own.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import get_args

from mail_dissect import models

SPEC = (Path(__file__).resolve().parent.parent / "docs" / "SPEC.md").read_text(encoding="utf-8")


def _unions_in_spec() -> list[frozenset[str]]:
    """Every `"a"|"b"|"c"` union written in the response-shape block."""
    unions = []
    for match in re.finditer(r'"[a-z_]+"(?:\s*\|\s*"[a-z_]+")+', SPEC):
        unions.append(frozenset(re.findall(r'"([a-z_]+)"', match.group(0))))
    return unions


def _taxonomy(label: str) -> frozenset[str]:
    """The `type` / `subtype` sets, written as a backticked list in §11.

    The two are written in one sentence, `type` ∈ … ; `subtype` ∈ … . so each is read up to
    its own terminator rather than to the end of the line.
    """
    terminator = ";" if label == "type" else r"\."
    pattern = rf"`{label}`(?: \(optional\))? ∈ (.+?){terminator}"
    match = re.search(pattern, SPEC, re.DOTALL)
    assert match, f"the specification no longer states the {label} set"
    return frozenset(re.findall(r"`([a-z0-9]+)`", match.group(1)))


def test_tool_states_match_the_spec() -> None:
    assert frozenset(get_args(models.ToolState)) in _unions_in_spec()


def test_artifact_kinds_match_the_spec() -> None:
    assert frozenset(get_args(models.ArtifactKind)) in _unions_in_spec()


def test_flags_match_the_spec() -> None:
    assert frozenset(get_args(models.Flag)) in _unions_in_spec()


def test_source_kinds_match_the_spec() -> None:
    assert frozenset(get_args(models.SourceKind)) in _unions_in_spec()


def test_resource_elements_match_the_spec() -> None:
    assert frozenset(get_args(models.ResourceElement)) in _unions_in_spec()


def test_observable_taxonomy_matches_the_spec() -> None:
    assert frozenset(get_args(models.ObservableType)) == _taxonomy("type")
    assert frozenset(get_args(models.ObservableSubtype)) == _taxonomy("subtype")
