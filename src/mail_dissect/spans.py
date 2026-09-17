"""Byte-level work over the raw message: the cheap pre-pass, and locating a part's bytes.

Two narrow jobs, both of which the standard library cannot do for us:

* **Limits before cost** `[D13]`. `MAX_MIME_PARTS` and `MAX_NESTING_DEPTH` are established by
  counting delimiters in the raw bytes, before a tree exists. A limit checked on a finished
  tree protects against the size of the result but not against the work already done, and a
  message of a million small parts must be cut during the scan (F3).
* **Original bytes** `[D12]`. The `eml` artifact carries the bytes that were in the input, and
  re-serialising a parsed message reproduces them only when the input was already canonical
  (F1). So the span is located here and verified against the tree the standard library built.

RFC 2046 §5.1.1 traps that this code exists to get right, and the fuzzer exists to keep right:
a delimiter is a line of its own, transport padding may follow it, the CRLF *preceding* a
delimiter belongs to the delimiter and not to the part, and one boundary may be a prefix of
another (`--BB` must not match the delimiter line of boundary `BBX`).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from itertools import pairwise

_BOUNDARY_PARAM = re.compile(rb'boundary\s*=\s*(?:"([^"]+)"|([^\s;"]+))', re.IGNORECASE)
_MESSAGE_RFC822 = re.compile(rb"message/rfc822", re.IGNORECASE)
_LWSP = b" \t"


@dataclass(frozen=True, slots=True)
class Estimate:
    """An upper bound on the work a message would cost, computed without parsing it."""

    parts: int
    containers: int
    nested_messages: int
    over_parts: bool
    over_depth: bool

    @property
    def over_limit(self) -> bool:
        return self.over_parts or self.over_depth


def boundaries(raw: bytes) -> list[bytes]:
    """Every `boundary=` value declared anywhere in the message, in order of appearance.

    Reading the parameters is what makes the count exact: searching for `\\n--` instead would
    also find the `-- ` signature separator that ordinary mail is full of, and a limit that
    fires on a legitimate message is worse than no limit.
    """
    seen: list[bytes] = []
    for match in _BOUNDARY_PARAM.finditer(raw):
        value = match.group(1) or match.group(2)
        if value and value not in seen:
            seen.append(value)
    return seen


def _delimiter_positions(
    raw: bytes,
    boundary: bytes,
    limit: int | None = None,
    region: tuple[int, int] | None = None,
) -> list[tuple[int, int, bool]]:
    """`(line start, offset after the line, is closing)` for every delimiter of `boundary`.

    `limit` stops the scan once that many have been found, which is what keeps the pre-pass
    bounded on an adversarial message: neither the count nor the cut needs to walk a million
    delimiters to know that five hundred is already too many.
    """
    marker = b"--" + boundary
    start, stop = region or (0, len(raw))
    positions: list[tuple[int, int, bool]] = []
    # Searching within a region rather than over a slice: a container nested in a 50 MB
    # message must not cost a 50 MB copy to walk.
    index = raw.find(marker, start, stop)
    while index != -1:
        if limit is not None and len(positions) >= limit:
            break
        at_line_start = index == 0 or raw[index - 1 : index] == b"\n"
        if at_line_start:
            cursor = index + len(marker)
            closing = raw[cursor : cursor + 2] == b"--"
            if closing:
                cursor += 2
            # Transport padding: whitespace between the delimiter and its line ending.
            while cursor < len(raw) and raw[cursor : cursor + 1] in (b" ", b"\t"):
                cursor += 1
            if raw[cursor : cursor + 2] == b"\r\n":
                positions.append((index, cursor + 2, closing))
            elif raw[cursor : cursor + 1] == b"\n":
                positions.append((index, cursor + 1, closing))
            elif cursor == len(raw):
                positions.append((index, cursor, closing))
            # Anything else means this line only starts like our delimiter - the case of one
            # boundary being a prefix of another, which must not be treated as a match.
        index = raw.find(marker, index + 1, stop)
    return positions


def part_blocks(
    raw: bytes, boundary: bytes, region: tuple[int, int] | None = None
) -> list[tuple[int, int]]:
    """Byte spans of each part of one multipart level, headers included.

    The span ends before the CRLF that introduces the next delimiter, because that CRLF
    belongs to the delimiter (RFC 2046 §5.1.1) and counting it in would change every hash.
    """
    positions = _delimiter_positions(raw, boundary, region=region)
    blocks: list[tuple[int, int]] = []
    for (_, start, closing), (next_start, _, _) in pairwise(positions):
        if closing:
            break
        end = next_start
        if raw[end - 2 : end] == b"\r\n":
            end -= 2
        elif raw[end - 1 : end] == b"\n":
            end -= 1
        blocks.append((start, end))
    return blocks


def body_span(raw: bytes, start: int, end: int) -> tuple[int, int]:
    """Where the body of a part block begins: after its first empty line."""
    window = raw[start:end]
    for separator in (b"\r\n\r\n", b"\n\n"):
        found = window.find(separator)
        if found != -1:
            return start + found + len(separator), end
    # A block with no empty line has no body; the headers ran to its end.
    return end, end


def estimate(raw: bytes, max_parts: int, max_depth: int) -> Estimate:
    """Bound the cost of parsing this message without parsing it `[D13]`.

    `parts` is capped at one past the limit: the question the pre-pass has to answer is "is
    this more than we agreed to do", not "how much more".
    """
    found = boundaries(raw)
    parts = 0
    for boundary in found:
        remaining = max_parts + 1 - parts
        if remaining <= 0:
            break
        found_here = _delimiter_positions(raw, boundary, limit=remaining)
        parts += sum(1 for _, _, closing in found_here if not closing)
    # Counted, not collected: a pathological message can mention the type a million times,
    # and the only question is whether it is more than the limit allows.
    nested = 0
    for _ in _MESSAGE_RFC822.finditer(raw):
        nested += 1
        if nested > max_depth and nested > max_parts:
            break
    total_parts = parts + 1 + nested  # the message itself, plus each nested message's root
    return Estimate(
        parts=total_parts,
        containers=len(found),
        nested_messages=nested,
        over_parts=total_parts > max_parts,
        # Both counts are upper bounds on depth: every container and every nested message can
        # contribute at most one level, and they can only all count if they are all nested.
        over_depth=len(found) > max_depth or nested > max_depth,
    )


def cut_to_part_limit(raw: bytes, max_parts: int) -> bytes:
    """Return the prefix that holds at most `max_parts` parts.

    Parsing a bounded prefix is what keeps the cost bounded: the alternative is to build the
    whole tree and then discover it was too big, which is the failure `[D13]` exists to
    prevent. The prefix is deliberately left unterminated - the caller knows it truncated and
    does not read the resulting "missing close boundary" as damage in the material.
    """
    starts: list[int] = []
    for boundary in boundaries(raw):
        # The overall n-th delimiter is among the first n+1 of each boundary, so collecting
        # that many per boundary is enough - and it stops each scan early.
        starts.extend(
            start
            for start, _, closing in _delimiter_positions(raw, boundary, limit=max_parts + 1)
            if not closing
        )
    if len(starts) <= max_parts:
        return raw
    starts.sort()
    return raw[: starts[max_parts]]
