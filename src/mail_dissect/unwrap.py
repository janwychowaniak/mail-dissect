"""Unwrapping addresses that mail filters rewrote (SPEC §10).

The table is declarative and empty by default. Providing a ready-made list would be a choice
about whose filters matter, and a regular expression from configuration cannot be validated
at startup or carried between deployments.

**Reversibility is the result of trying, not a declaration.** The service cannot know which
wrappers are irreversible; it knows only whether it can unwrap an entry from the table. A
wrapper with no entry passes through unchanged — and never, under any circumstance, by asking
the network.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlsplit

from .settings import UnwrapperRule

MAX_PASSES = 4


@dataclass(frozen=True, slots=True)
class UnwrapResult:
    href: str
    rewritten_from: str | None = None
    failed: bool = False


class Unwrapper:
    """The configured table, applied to a fixed point."""

    __slots__ = ("_rules",)

    def __init__(self, rules: list[UnwrapperRule]) -> None:
        self._rules = rules

    @property
    def configured(self) -> bool:
        return bool(self._rules)

    def apply(self, href: str) -> UnwrapResult:
        """Unwrap repeatedly until nothing matches, or a hard limit of passes.

        Mail is sometimes passed through two gateways, so one pass is not enough; a hard
        limit is what keeps a wrapper that unwraps to itself from spinning. `rewritten_from`
        carries the OUTERMOST address — the one that actually stood in the message.
        """
        if not self._rules:
            return UnwrapResult(href=href)

        original = href
        current = href
        failed = False
        for _ in range(MAX_PASSES):
            rule = self._match(current)
            if rule is None:
                break
            target = _extract(current, rule)
            if target is None:
                # The entry matched and the target could not be taken out: that is a broken
                # configuration or a changed wrapper, and it must not look like "there was
                # nothing to unwrap" (SPEC §10).
                failed = True
                break
            if target == current:
                break
            current = target
        if current == original:
            return UnwrapResult(href=original, rewritten_from=None, failed=failed)
        return UnwrapResult(href=current, rewritten_from=original, failed=failed)

    def _match(self, href: str) -> UnwrapperRule | None:
        host = (urlsplit(href).hostname or "").lower()
        if not host:
            return None
        for rule in self._rules:
            # By suffix, on a label boundary: `evil-safelinks.example` must not match a rule
            # written for `safelinks.example`.
            if host == rule.host_suffix or host.endswith(f".{rule.host_suffix}"):
                return rule
        return None


def _extract(href: str, rule: UnwrapperRule) -> str | None:
    parts = urlsplit(href)
    kind, _, argument = rule.source.partition(":")
    if kind == "query":
        values = parse_qs(parts.query, keep_blank_values=True).get(argument)
        raw = values[0] if values else None
    else:
        segments = [segment for segment in parts.path.split("/") if segment]
        index = int(argument)
        raw = segments[index] if index < len(segments) else None
    if raw is None:
        return None

    decoded = _decode(raw, rule.decoder)
    if decoded is None:
        return None
    if rule.strip_prefix and decoded.startswith(rule.strip_prefix):
        decoded = decoded[len(rule.strip_prefix) :]
    if rule.strip_suffix and decoded.endswith(rule.strip_suffix):
        decoded = decoded[: -len(rule.strip_suffix)]
    return decoded or None


def _decode(value: str, decoder: str) -> str | None:
    if decoder == "none":
        return value
    if decoder == "percent":
        return unquote(value)
    try:
        padded = value + "=" * (-len(value) % 4)
        if decoder == "base64url":
            return base64.urlsafe_b64decode(padded).decode("utf-8", "replace")
        return base64.b64decode(padded, validate=True).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return None
