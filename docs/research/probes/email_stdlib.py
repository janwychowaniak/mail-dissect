"""Probes for CPython's `email` package on the inputs mail-dissect must survive.

Run:  python3.13 docs/research/probes/email_stdlib.py

Findings F1 to F10 and F17 in ../NOTES.md are produced by one function each here. The probes are
read-only, offline, and depend on nothing but the standard library, so anyone
can re-run them against a newer interpreter and see whether a finding still
holds. Print output is the evidence; keep it terse enough to paste.
"""

from __future__ import annotations

import email
import email.policy
import sys
import time
from email import message_from_bytes
from email.generator import BytesGenerator
from email.headerregistry import HeaderRegistry
from email.parser import BytesParser
from io import BytesIO

CRLF = b"\r\n"


def _banner(tag: str, title: str) -> None:
    print(f"\n=== {tag}: {title} ===")


def f1_nested_reserialisation_is_not_byte_identical() -> None:
    """Where does re-serialising a nested message stop reproducing the input?"""
    _banner("F1", "nested message/rfc822 re-serialisation")

    def roundtrip(inner: bytes) -> bytes:
        outer = CRLF.join(
            [
                b"Content-Type: multipart/mixed; boundary=BB",
                b"",
                b"--BB",
                b"Content-Type: message/rfc822",
                b"",
                inner,
                b"--BB--",
                b"",
            ]
        )
        msg = message_from_bytes(outer, policy=email.policy.compat32)
        nested = list(msg.walk())[1].get_payload(0)
        buf = BytesIO()
        BytesGenerator(buf, policy=email.policy.SMTP).flatten(nested)
        return buf.getvalue()

    cases = {
        "already canonical": CRLF.join([b"From: a@example.com", b"", b"body"]),
        "tab continuation": b"Subject: a" + CRLF + b"\tcontinued" + CRLF + CRLF + b"body",
        "LF-only line endings": b"From: a@example.com\nSubject: s\n\nbody",
        "long header": b"Subject: " + b"word " * 40 + CRLF + CRLF + b"body",
        "no space after colon": b"From:a@example.com" + CRLF + CRLF + b"body",
        "8-bit header bytes": b"Subject: caf\xe9" + CRLF + CRLF + b"body",
        "no body at all": b"From: a@example.com" + CRLF,
        "space before colon, only header": b"From : a@example.com" + CRLF + CRLF + b"body",
        "space before colon, among valid": CRLF.join(
            [b"From: a@example.com", b"X-Broken : yes", b"Subject: s", b"", b"body"]
        ),
    }
    for label, inner in cases.items():
        rebuilt = roundtrip(inner)
        identical = rebuilt == inner
        print(f"{label:22s} identical={identical}")
        if not identical:
            print(f"    input   : {inner!r}")
            print(f"    rebuilt : {rebuilt!r}")


def f1b_header_line_traps() -> None:
    """Why do malformed header lines disappear? Two different mechanisms."""
    _banner("F1b", "header lines with a space before the colon")
    from email.feedparser import headerRE

    print(f"feedparser.headerRE = {headerRE.pattern}")
    for line in ("From : a@example.com", "X-Broken : yes", "From: ok@example.com"):
        print(f"    {line!r:26s} matches={bool(headerRE.match(line))}")
    cases = {
        "only header, starts with 'From '": b"From : a@example.com\r\n\r\nbody",
        "among valid headers": (b"From: a@example.com\r\nX-Broken : yes\r\nSubject: s\r\n\r\nbody"),
    }
    for label, raw in cases.items():
        msg = message_from_bytes(raw, policy=email.policy.compat32)
        print(f"{label}:")
        print(f"    headers  = {msg.items()}")
        print(f"    unixfrom = {msg.get_unixfrom()!r}")
        print(f"    defects  = {[type(d).__name__ for d in msg.defects]}")
        print(f"    payload  = {msg.get_payload()!r}")


def f2_base64_nested_message_is_parsed_as_text() -> None:
    """A transport-encoded message/rfc822 part: does the tree stay correct?"""
    _banner("F2", "message/rfc822 with Content-Transfer-Encoding: base64")
    import base64

    inner = CRLF.join([b"From: a@example.com", b"Subject: inner", b"", b"hello", b""])
    encoded = base64.b64encode(inner)
    outer = CRLF.join(
        [
            b"Content-Type: multipart/mixed; boundary=BB",
            b"",
            b"--BB",
            b"Content-Type: message/rfc822",
            b"Content-Transfer-Encoding: base64",
            b"",
            encoded,
            b"--BB--",
            b"",
        ]
    )
    for name, policy in (("compat32", email.policy.compat32), ("default", email.policy.default)):
        msg = message_from_bytes(outer, policy=policy)
        types = [p.get_content_type() for p in msg.walk()]
        defects = [type(d).__name__ for p in msg.walk() for d in p.defects]
        print(f"{name:9s} types={types} defects={defects}")


def f3_policy_cost() -> None:
    """How much does policy.default cost on a message with many small parts?"""
    _banner("F3", "parse cost, compat32 vs default")
    for count in (5_000, 50_000):
        parts = b"".join(
            CRLF.join([b"--BB", b"Content-Type: text/plain", b"", b"x", b""]) for _ in range(count)
        )
        raw = (
            CRLF.join([b"Content-Type: multipart/mixed; boundary=BB", b"", b""])
            + parts
            + b"--BB--"
            + CRLF
        )
        for name, policy in (
            ("compat32", email.policy.compat32),
            ("default", email.policy.default),
        ):
            start = time.perf_counter()
            msg = BytesParser(policy=policy).parsebytes(raw)
            parsed = time.perf_counter() - start
            start = time.perf_counter()
            walked = sum(1 for _ in msg.walk())
            walk = time.perf_counter() - start
            print(
                f"{count:>6} parts  {name:9s} size={len(raw) / 1e6:5.1f} MB  "
                f"parse={parsed:6.2f}s  walk={walk:5.2f}s  parts_seen={walked}"
            )


def f4_filename_extraction() -> None:
    """Which policy reads RFC 2231 and RFC 2047 filenames correctly?"""
    _banner("F4", "attachment filename extraction")
    cases = {
        "RFC 2231 encoded": b"Content-Disposition: attachment; filename*=UTF-8''%E2%82%AC.txt",
        "RFC 2231 continued": (
            b'Content-Disposition: attachment; filename*0="long-"; filename*1="name.txt"'
        ),
        "RFC 2047 in filename": (
            b'Content-Disposition: attachment; filename="=?utf-8?q?caf=C3=A9.txt?="'
        ),
        "plain quoted": b'Content-Disposition: attachment; filename="plain.txt"',
        "path in filename": b'Content-Disposition: attachment; filename="../../etc/passwd"',
    }
    for label, header in cases.items():
        raw = header + CRLF + CRLF + b"x" + CRLF
        row = []
        for name, policy in (
            ("compat32", email.policy.compat32),
            ("default", email.policy.default),
        ):
            msg = message_from_bytes(raw, policy=policy)
            row.append(f"{name}={msg.get_filename()!r}")
        print(f"{label:22s} {'  '.join(row)}")


def f5_lone_surrogate_breaks_json() -> None:
    """Can a header make the response unserialisable on Starlette's JSON path?"""
    _banner("F5", "lone surrogate from an 8-bit header")
    import json

    raw = b"To: \xe9v@x.example\r\nSubject: \xe9\r\n\r\nbody\r\n"
    msg = message_from_bytes(raw, policy=email.policy.default)
    rendered = str(msg["to"].addresses[0].addr_spec)
    print(f"addr_spec repr: {rendered!r}")
    # Starlette's JSONResponse.render() uses ensure_ascii=False; the stdlib default
    # (ensure_ascii=True) escapes the surrogate instead and hides the problem, so a
    # probe written with plain json.dumps would clear this wrongly.
    for label, kwargs in (
        ("ensure_ascii=True (json default)", {}),
        ("ensure_ascii=False (Starlette)", {"ensure_ascii": False}),
    ):
        try:
            json.dumps(
                {"to": rendered}, allow_nan=False, indent=None, separators=(",", ":"), **kwargs
            ).encode("utf-8")
            print(f"    {label:34s} -> ok")
        except (UnicodeEncodeError, ValueError) as exc:
            print(f"    {label:34s} -> {type(exc).__name__}: {exc}")
    scrubbed = rendered.encode("utf-8", "replace").decode("utf-8")
    print(f"    after scrub: {scrubbed!r}  changed={scrubbed != rendered}")


def f6_address_header_registry_coverage() -> None:
    """Which of the spec's address headers does the stdlib registry decompose?"""
    _banner("F6", "HeaderRegistry coverage of address headers")
    registry = HeaderRegistry()
    names = [
        "from",
        "to",
        "cc",
        "bcc",
        "reply-to",
        "sender",
        "return-path",
        "resent-from",
        "resent-to",
        "resent-cc",
        "resent-sender",
        "resent-reply-to",
    ]
    for name in names:
        header = registry(name, "a@example.com")
        kind = type(header).__mro__[1].__name__
        print(f"{name:18s} class={kind:28s} addresses={hasattr(header, 'addresses')}")


def f7_rfc2047_decoding_paths() -> None:
    """make_header/decode_header vs the header registry on broken encoded words."""
    _banner("F7", "RFC 2047 decoding")
    from email.header import decode_header, make_header

    registry = HeaderRegistry()
    samples = [
        "=?utf-8?q?caf=C3=A9?=",
        "=?bogus-charset?Q?x?=",
        "=?utf-8?b?not-valid-base64!!?=",
        "plain ascii",
    ]
    for sample in samples:
        try:
            legacy = str(make_header(decode_header(sample)))
            legacy_note = repr(legacy)
        except Exception as exc:
            legacy_note = f"{type(exc).__name__}: {exc}"
        modern = str(registry("subject", sample))
        print(f"{sample!r}\n    make_header -> {legacy_note}\n    registry    -> {modern!r}")


def f8_broken_encodings_do_not_raise() -> None:
    """Does the stdlib signal broken base64/QP and a garbage Content-Type?"""
    _banner("F8", "broken transfer encodings and garbage Content-Type")
    cases = {
        "base64 length 1 mod 4": b"Content-Transfer-Encoding: base64\r\n\r\nQUJDR\r\n",
        "base64 illegal chars": b"Content-Transfer-Encoding: base64\r\n\r\n!!!!\r\n",
        "quoted-printable cut": b"Content-Transfer-Encoding: quoted-printable\r\n\r\nabc=\r\n",
        "garbage content-type": b"Content-Type: ;;;garbage\r\n\r\nbody\r\n",
    }
    for label, raw in cases.items():
        msg = message_from_bytes(raw, policy=email.policy.compat32)
        payload = msg.get_payload(decode=True)
        defects = [type(d).__name__ for d in msg.defects]
        print(
            f"{label:24s} type={msg.get_content_type():12s} payload={payload!r} defects={defects}"
        )


def f10_html_parser_survives_hostile_input() -> None:
    """Does the stdlib HTML parser survive the shapes a hostile mail carries?"""
    _banner("F10", "html.parser on hostile input")
    from html.parser import HTMLParser

    class Counter(HTMLParser):
        def __init__(self) -> None:
            super().__init__(convert_charrefs=True)
            self.starts = 0
            self.chars = 0

        def handle_starttag(self, tag: str, attrs: object) -> None:
            self.starts += 1

        def handle_data(self, data: str) -> None:
            self.chars += len(data)

    cases = {
        "500k less-than": "<" * 500_000,
        "unterminated comment": "<!-- " + "a" * 100_000,
        "deep nesting": "<div>" * 50_000,
        "attribute storm": "<a " + " ".join(f'x{i}="{i}"' for i in range(20_000)) + ">t</a>",
        "NUL bytes": "a\x00b<c>\x00</c>",
        "unclosed quote": '<a href="http://example.com>text',
    }
    for label, doc in cases.items():
        parser = Counter()
        start = time.perf_counter()
        try:
            parser.feed(doc)
            parser.close()
            note = f"ok starts={parser.starts} chars={parser.chars}"
        except Exception as exc:
            note = f"{type(exc).__name__}: {exc}"
        print(f"{label:22s} {time.perf_counter() - start:6.2f}s  {note}")


def f17_compat32_hands_out_a_header_object() -> None:
    """What `compat32`, the policy the tree is read with, returns for an 8-bit header value."""
    _banner("F17", "an 8-bit header value under compat32, and what reads it afterwards")
    import codecs

    raw = b"X-Ok: cafe\r\nSubject: caf\xe9\r\nTo: \xe9v@x.example\r\n\r\nbody\r\n"
    for label, policy in (("compat32", email.policy.compat32), ("default", email.policy.default)):
        msg = message_from_bytes(raw, policy=policy)
        for name in ("X-Ok", "Subject", "To"):
            value = msg[name]
            kind = type(value).__name__
            where = f"msg[{name!r}]"
            print(f"{label:9s} {where:15s} {kind:26s} is str: {isinstance(value, str)}")
    stored = dict(message_from_bytes(raw, policy=email.policy.compat32).raw_items())["Subject"]
    print(f"compat32 raw_items() Subject: {stored!r}")
    registry = HeaderRegistry()
    for label, value in (
        ("8-bit byte", "caf\udce9"),
        ("raw UTF-8", "caf\udcc3\udca9"),
        ("encoded-word, bad UTF-8", "=?utf-8?q?caf=E9?="),
    ):
        header = registry("subject", value)
        print(f"registry {label:24s} -> {str(header)!r}  defects={len(header.defects)}")
    for disposition in (
        b"filename*=utf-8''caf%C3%A9.txt",
        b"filename*=utf-8''caf%E9.txt",
        b"filename*=x-no-such-charset''caf%E9.txt",
    ):
        part = message_from_bytes(
            b"Content-Disposition: attachment; " + disposition + b"\r\n\r\nx",
            policy=email.policy.compat32,
        )
        print(f"{disposition.decode():42s} -> {part.get_filename()!r}  defects={part.defects}")
    for name in ("caf\udce9", "utf\x00", "x-nonsense"):
        try:
            result = codecs.lookup(name).name
        except Exception as exc:
            result = f"{type(exc).__name__} (a LookupError: {isinstance(exc, LookupError)})"
        print(f"codecs.lookup({name!r}) -> {result}")


def main() -> int:
    print(f"python {sys.version}")
    f1_nested_reserialisation_is_not_byte_identical()
    f1b_header_line_traps()
    f2_base64_nested_message_is_parsed_as_text()
    f3_policy_cost()
    f4_filename_extraction()
    f5_lone_surrogate_breaks_json()
    f6_address_header_registry_coverage()
    f7_rfc2047_decoding_paths()
    f8_broken_encodings_do_not_raise()
    f10_html_parser_survives_hostile_input()
    f17_compat32_hands_out_a_header_object()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
