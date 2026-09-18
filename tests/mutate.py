"""Programmatic damage for the resilience tests (SPEC §18).

Take a correct synthetic message and break it on purpose. Every mutator here is one of the
shapes the specification names, and each returns its own name so a failure says what was done
rather than only which seed did it.
"""

from __future__ import annotations

import random
from collections.abc import Callable

Mutator = Callable[[bytes, random.Random], bytes]


def truncate(raw: bytes, rng: random.Random) -> bytes:
    """Cut the message at a random offset - the shape a failed transfer leaves."""
    if len(raw) < 2:
        return raw
    return raw[: rng.randrange(1, len(raw))]


def drop_header(raw: bytes, rng: random.Random) -> bytes:
    head, separator, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    if len(lines) < 2:
        return raw
    del lines[rng.randrange(len(lines))]
    return b"\r\n".join(lines) + separator + body


def duplicate_header(raw: bytes, rng: random.Random) -> bytes:
    head, separator, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    if not lines:
        return raw
    index = rng.randrange(len(lines))
    lines.insert(index, lines[index])
    return b"\r\n".join(lines) + separator + body


def header_without_colon(raw: bytes, rng: random.Random) -> bytes:
    head, separator, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    if not lines:
        return raw
    index = rng.randrange(len(lines))
    lines[index] = lines[index].replace(b":", b"", 1)
    return b"\r\n".join(lines) + separator + body


def corrupt_encoded_payload(raw: bytes, rng: random.Random) -> bytes:
    """Break base64 or quoted-printable in the body, where the decoder has to cope."""
    head, separator, body = raw.partition(b"\r\n\r\n")
    if not body:
        return raw
    position = rng.randrange(len(body))
    return head + separator + body[:position] + b"!!" + body[position + 1 :]


def mislabel_charset(raw: bytes, _: random.Random) -> bytes:
    return raw.replace(b"charset=", b"charset=definitely-not-a-charset-", 1)


def break_boundary(raw: bytes, rng: random.Random) -> bytes:
    """Change one delimiter so it no longer matches the declared boundary."""
    if b"--BB" not in raw:
        return raw
    occurrences = raw.count(b"--BB")
    target = rng.randrange(occurrences)
    parts = raw.split(b"--BB")
    return b"--BB".join(parts[: target + 1]) + b"--BX" + b"--BB".join(parts[target + 1 :])


def remove_closing_boundary(raw: bytes, _: random.Random) -> bytes:
    return raw.replace(b"--BB--", b"", 1)


def empty_parts(raw: bytes, _: random.Random) -> bytes:
    return raw.replace(b"--BB\r\n", b"--BB\r\n\r\n--BB\r\n", 1)


def deep_nesting(raw: bytes, _: random.Random) -> bytes:
    """Wrap the message in more `message/rfc822` layers than the limit allows."""
    wrapped = raw
    for index in range(8):
        boundary = f"N{index}".encode()
        wrapped = (
            b'Content-Type: multipart/mixed; boundary="' + boundary + b'"\r\n\r\n'
            b"--"
            + boundary
            + b"\r\nContent-Type: message/rfc822\r\n\r\n"
            + wrapped
            + b"\r\n--"
            + boundary
            + b"--\r\n"
        )
    return wrapped


def very_long_line(raw: bytes, rng: random.Random) -> bytes:
    head, separator, body = raw.partition(b"\r\n\r\n")
    return head + b"\r\nX-Long: " + b"a" * rng.randrange(1000, 50_000) + separator + body


def control_bytes(raw: bytes, rng: random.Random) -> bytes:
    data = bytearray(raw)
    for _ in range(rng.randrange(1, 20)):
        data[rng.randrange(len(data))] = rng.choice([0x00, 0x01, 0x07, 0x1B, 0x7F])
    return bytes(data)


def mixed_line_endings(raw: bytes, rng: random.Random) -> bytes:
    parts = raw.split(b"\r\n")
    return (
        b"".join(part + (b"\n" if rng.random() < 0.5 else b"\r\n") for part in parts[:-1])
        + parts[-1]
    )


MUTATORS: tuple[Mutator, ...] = (
    truncate,
    drop_header,
    duplicate_header,
    header_without_colon,
    corrupt_encoded_payload,
    mislabel_charset,
    break_boundary,
    remove_closing_boundary,
    empty_parts,
    deep_nesting,
    very_long_line,
    control_bytes,
    mixed_line_endings,
)


def mutate(raw: bytes, rng: random.Random) -> tuple[str, bytes]:
    """Apply one or two mutators; returns what was done and the damaged bytes."""
    chosen = rng.sample(MUTATORS, k=rng.choice([1, 1, 2]))
    damaged = raw
    for mutator in chosen:
        damaged = mutator(damaged, rng)
    return "+".join(m.__name__ for m in chosen), damaged
