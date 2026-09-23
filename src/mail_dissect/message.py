"""One message, dissected: headers, parts, bodies — and the messages inside it (SPEC §6).

Pure and synchronous on purpose: no I/O, no clock, no network. Everything here is a function
of the input bytes alone, which is what makes the determinism criterion (§17) testable and
what lets the orchestrator run this in a worker thread without dragging state along.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from .headers import (
    Address,
    AuthResult,
    Hop,
    addresses_of,
    header_map,
    parse_auth_results,
    parse_received,
)
from .mimetree import Tree, parse_tree


@dataclass(slots=True)
class ParsedMessage:
    """One entry of `messages[]`, plus the bytes it was read from."""

    index: int
    depth: int
    raw: bytes
    headers: dict[str, list[str]] = field(default_factory=dict)
    addresses: dict[str, list[Address]] = field(default_factory=dict)
    auth: list[AuthResult] = field(default_factory=list)
    received: list[Hop] = field(default_factory=list)
    tree: Tree = field(default_factory=Tree)
    flags: set[str] = field(default_factory=set)


@dataclass(slots=True)
class Dissection:
    messages: list[ParsedMessage] = field(default_factory=list)
    flags: set[str] = field(default_factory=set)


def parse_message(
    raw: bytes, index: int, depth: int, *, max_attachment_bytes: int, max_parts: int
) -> ParsedMessage:
    """Dissect one message. The top-level message is dissected exactly like a nested one."""
    parsed = ParsedMessage(index=index, depth=depth, raw=raw)
    header_block = _header_block(raw)
    parsed.headers, substituted = header_map(header_block)
    if substituted:
        parsed.flags.add("encoding_fallback")
    parsed.addresses = addresses_of(header_block)
    parsed.received = [parse_received(value) for value in parsed.headers.get("received", [])]
    for value in parsed.headers.get("authentication-results", []):
        parsed.auth.extend(parse_auth_results(value))
    parsed.tree = parse_tree(raw, max_attachment_bytes=max_attachment_bytes, max_parts=max_parts)
    return parsed


def dissect_messages(
    raw: bytes,
    *,
    max_attachment_bytes: int,
    max_parts: int,
    max_depth: int,
    should_stop: Callable[[], bool] | None = None,
) -> Dissection:
    """The top-level message and every message nested inside it, in order of appearance.

    Depth-first: a message nested inside a nested message appears within the first one's
    bytes, so reading order and document order are the same thing. The part budget is shared
    across all of them, because a nested message's parts are the dissection's parts too - and
    the alternative would let nesting multiply a limit that exists to bound the work.

    `should_stop` is the whole-dissection deadline, asked BETWEEN messages `[D10]`. It is a
    plain predicate rather than a clock, so this module stays a pure function of its input:
    the caller owns the time, and the test that proves `truncated` owns it too.
    """
    result = Dissection()
    pending: list[tuple[bytes, int]] = [(raw, 0)]
    remaining = max_parts

    while pending:
        current, depth = pending.pop(0)
        if remaining <= 0 or (should_stop is not None and should_stop()):
            result.flags.add("truncated")
            break
        message = parse_message(
            current,
            index=len(result.messages),
            depth=depth,
            max_attachment_bytes=max_attachment_bytes,
            max_parts=remaining,
        )
        result.messages.append(message)
        result.flags |= message.tree.flags | message.flags
        remaining -= len(message.tree.parts)

        if depth >= max_depth:
            # Deeper than we agreed to go: the result is partial, not an error (SPEC §15).
            if message.tree.nested:
                result.flags.add("truncated")
            continue
        children: list[tuple[bytes, int]] = []
        for part_index in message.tree.nested:
            payload = message.tree.parts[part_index].nested_bytes
            if payload:
                children.append((payload, depth + 1))
        # Depth-first: the nested messages of this one come before this one's siblings.
        pending = children + pending

    return result


def _header_block(raw: bytes) -> bytes:
    """The header block, up to and not including the first empty line."""
    for separator in (b"\r\n\r\n", b"\n\n"):
        found = raw.find(separator)
        if found != -1:
            return raw[:found]
    return raw
