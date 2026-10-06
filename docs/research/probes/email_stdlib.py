"""Probes for CPython's `email` package on the inputs mail-dissect must survive.

Run:  python3.13 docs/research/probes/email_stdlib.py

Findings F1 to F10, F17 to F19, F21 and F23 to F27 in ../NOTES.md are produced by one function
each here.
The probes are read-only, offline, and depend on nothing but the standard library, so
anyone can re-run them against a newer interpreter and see whether a finding still
holds. Print output is the evidence; keep it terse enough to paste.
"""

from __future__ import annotations

import contextlib
import email
import email.policy
import itertools
import random
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


def f18_the_registry_does_not_unfold() -> None:
    """What `compat32` stores for a folded header, and what the header registry makes of it."""
    _banner("F18", "a folded header value under compat32, handed to the header registry")
    raw = (
        b"From: Alice Example\r\n\t<alice@example.net>\r\n"
        b"Subject: =?utf-8?q?exam?=\r\n =?utf-8?q?ple?=\r\n"
        b"X-Note: first\r\n second\r\n"
        b"Content-Type: text/plain;\r\n charset=utf-8\r\n"
        b"X-After-Colon:\r\n value\r\n"
        b"\r\nbody\r\n"
    )
    stored = message_from_bytes(raw, policy=email.policy.compat32)
    reference = message_from_bytes(raw, policy=email.policy.default)
    registry = HeaderRegistry()
    splitter = email.policy.linesep_splitter

    def through_registry(name: str, value: str) -> str:
        try:
            header = registry(name, value)
        except Exception as exc:
            return f"{type(exc).__name__}: {exc}"
        return f"{str(header)!r}  defects={len(header.defects)}"

    for name in ("From", "Subject", "X-Note", "Content-Type", "X-After-Colon"):
        value = stored[name]
        unfolded = "".join(splitter.split(value))
        print(f"{name}: compat32 holds {value!r}")
        print(f"    registry, as held     -> {through_registry(name, value)}")
        print(f"    registry, unfolded    -> {through_registry(name, unfolded)}")
        print(f"    registry, and lstrip  -> {through_registry(name, unfolded.lstrip(' \t'))}")
        print(f"    policy.default        -> {str(reference[name])!r}")
    print(f"policy.default unfolds with {splitter.pattern!r} before its registry sees a value")
    kinds: dict[str, list[str]] = {}
    for name, cls in sorted(registry.registry.items()):
        kinds.setdefault(cls.__name__, []).append(name)
    for kind, names in sorted(kinds.items()):
        print(f"registry map  {kind:30s} {', '.join(names)}")
    print(f"registry map  default: {registry.default_class.__name__}")


def f19_an_address_written_inside_quotes() -> None:
    """What the registry returns for a quoted string where an address goes, read once more."""
    _banner("F19", "an address header holding a quoted string, and its local part read again")
    registry = HeaderRegistry()
    shapes = [
        '"Bob Example <bob@example.net>"',
        '"bob@example.net"',
        '"Bob Example <bob@example.net> via list"',
        '"Bob <bob@example.net> <eve@example.org>"',
        '"bob@example.net, eve@example.org"',
        '"Bob Example"',
        '"bob@example.net".x',
        '"first@example.org" <second@example.net>',
    ]
    for shape in shapes:
        for entry in registry("from", shape).addresses:
            first = f"{entry.addr_spec!r} domain={entry.domain!r}"
            if entry.domain:
                print(f"{shape}\n    parsed: {first}  (has a domain)")
                continue
            again = registry("from", entry.username)
            boxes = [(a.display_name, a.addr_spec) for a in again.addresses]
            defects = sorted({type(d).__name__ for d in again.defects})
            print(f"{shape}\n    parsed: {first}")
            print(f"    local part read again: {len(boxes)} mailbox(es) {boxes} defects={defects}")


def f21_a_filename_read_by_three_grammars() -> None:
    """A name with encoded-words: the grammar of `Content-Disposition` given the bare name, the
    grammar of unstructured text, and `policy.default`'s own reading of the parameter."""
    _banner("F21", "a filename read by three grammars")
    registry = HeaderRegistry()
    resume = "=?utf-8?Q?r=C3=A9sum=C3=A9?="
    names = {
        "two words": "=?utf-8?Q?na=C3=AFve-no?= =?utf-8?Q?tes.txt?=",
        "split in extension": "=?utf-8?Q?notes.t?= =?utf-8?Q?xt?=",
        "word ;v2": f"{resume};v2.pdf",
        "word ;x=y": f"{resume};x=y.pdf",
        'word \\"': f'{resume}".pdf',
        "word, text": f"{resume} notes.pdf",
    }
    print("the bare name given to the registry:")
    for label, name in names.items():
        as_disposition = str(registry("content-disposition", name))
        as_unstructured = str(registry("x-filename", name))
        print(f"  {label:20s} disposition={as_disposition!r}  unstructured={as_unstructured!r}")
    words = "=?utf-8?Q?na=C3=AFve-no?= =?utf-8?Q?tes.txt?="
    parameters = {
        "continued, ws at boundary": 'filename*0="=?utf-8?Q?na=C3=AFve-no?= "; '
        'filename*1="=?utf-8?Q?tes.txt?="',
        "charset form, word inside": "filename*=utf-8''%3D%3Futf-8%3FQ%3Fx%3F%3D.pdf",
        "plain, then charset form": "filename=\"plain.pdf\"; filename*=utf-8''r%C3%A9sum%C3%A9.pdf",
        "charset form, then plain": "filename*=utf-8''r%C3%A9sum%C3%A9.pdf; filename=\"plain.pdf\"",
        "white space, periods": 'filename=" .notes. "',
        "two words, plain": f'filename="{words}"',
    }
    print("the parameter, read by each policy:")
    for label, params in parameters.items():
        raw = f"Content-Disposition: attachment; {params}".encode() + CRLF + CRLF + b"x" + CRLF
        compat32 = message_from_bytes(raw, policy=email.policy.compat32).get_filename()
        default = message_from_bytes(raw, policy=email.policy.default)
        print(
            f"  {label:26s} compat32={compat32!r}  default={default.get_filename()!r}  "
            f"default header={str(default['content-disposition'])!r}"
        )


def f23_html_parser_fed_in_pieces() -> None:
    """Does html.parser read the same document fed at once and fed in pieces cut before a `<`?"""
    _banner("F23", "html.parser fed in pieces")
    from html.parser import HTMLParser

    class Recorder(HTMLParser):
        def __init__(self) -> None:
            super().__init__(convert_charrefs=True)
            self.events: list[tuple[str, str]] = []

        def handle_starttag(self, tag: str, attrs: object) -> None:
            self.events.append(("start", tag))

        def handle_endtag(self, tag: str) -> None:
            self.events.append(("end", tag))

        def handle_data(self, data: str) -> None:
            self.events.append(("data", data))

        def handle_comment(self, data: str) -> None:
            self.events.append(("comment", data))

    def read(pieces: list[str]) -> list[tuple[str, str]]:
        parser = Recorder()
        for piece in pieces:
            parser.feed(piece)
        parser.close()
        return parser.events

    def before_lt(doc: str, size: int) -> list[str]:
        """Pieces of at least `size` characters, each cut just before a `<`."""
        pieces, start = [], 0
        while len(doc) - start > size:
            cut = doc.find("<", start + size)
            if cut < 0:
                break
            pieces.append(doc[start:cut])
            start = cut
        return [*pieces, doc[start:]]

    for doc in ("<!--><b>x</b>-->", "<!---><b>x</b>-->", "<!-- c --><b>x</b>"):
        cut = doc.index("<b>")
        whole, split = read([doc]), read([doc[:cut], doc[cut:]])
        print(f"{doc!r:22s} at once={whole}")
        print(f"{'':22s} in two={split}  same={whole == split}")

    pieces = [
        "word ",
        "a&amp;b ",
        "a & b ",
        "x&y",
        "&",
        "a < b ",
        "<",
        "<3 ",
        "<p>",
        "</p>",
        "<br/>",
        '<a href="h">',
        "</a>",
        '<span title="x<y>z">',
        "</span>",
        "<!-- c < d -->",
        "-->",
        "<style>",
        "a<b {}",
        "</styl",
        "</style>",
        "<script>",
        "if (a < b) {}",
        "</scr",
        "</script>",
        "<![CDATA[x<y]]>",
        "<!DOCTYPE html>",
        "<?pi?>",
        "</ x>",
        "<a",
        "</",
        "\n",
    ]
    openers = ["<!-->", "<!--"]
    for label, alphabet in (("with <!--> and <!--", pieces + openers), ("without them", pieces)):
        rng = random.Random(23)
        docs = [
            "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 60))) for _ in range(2000)
        ]
        differ = sum(
            read(before_lt(doc, size)) != read([doc]) for doc in docs for size in (1, 3, 8)
        )
        control = sum(
            read([doc[i : i + 3] for i in range(0, len(doc), 3)]) != read([doc]) for doc in docs
        )
        print(
            f"{label:20s} pieces cut before '<' differ in {differ} of {len(docs) * 3}; "
            f"control, cut every 3 characters: {control} of {len(docs)}"
        )


def f24_the_header_parser_cost() -> None:
    """What does the header registry cost on a long value, and what makes it grow?"""
    _banner("F24", "the header parser's cost")
    registry = HeaderRegistry()

    def cost(name: str, value: str) -> float:
        start = time.perf_counter()
        with contextlib.suppress(Exception):
            str(registry(name, value))
        return time.perf_counter() - start

    unstructured = {
        "one token": "a",
        "a 7-letter word and a space": "abcdefg ",
        "a letter and a space": "a ",
        "=?a and a space (no encoded-word)": "=?a ",
        "=?utf-8?q?a?= and a space": "=?utf-8?q?a?= ",
    }
    for label, unit in unstructured.items():
        cells = []
        for size in (16_000, 32_000, 64_000):
            value = (unit * (size // len(unit) + 1))[:size]
            cells.append(f"{size // 1000}k {cost('subject', value):.3f}s")
        print(f"  Subject, {label:36} " + "  ".join(cells))
    # The same shape over a wider range, best of two: where the per-step cost still dominates,
    # twice the input reads about twice the time, and the square shows only further up.
    sizes = (16_000, 32_000, 64_000, 128_000, 256_000)
    times = [min(cost("subject", ("a " * size)[:size]) for _ in range(2)) for size in sizes]
    ratios = "  ".join(f"x{b / a:.2f}" for a, b in itertools.pairwise(times))
    print(f"  Subject, a letter and a space, 16k to 256k: {times[-1]:.2f}s at 256k; {ratios}")
    structured = [
        ("content-type", "(a)"),
        ("content-type", "text/plain;"),
        ("cc", "."),
        ("references", ","),
        ("to", '"'),
        ("message-id", "(a)"),
        ("date", "(a)"),
    ]
    for name, unit in structured:
        cells = []
        for size in (2_000, 4_000, 8_000):
            value = (
                unit[:-1] + (unit[-1] * size) if unit.endswith(";") else unit * (size // len(unit))
            )
            cells.append(f"{size // 1000}k {cost(name, value[:size]):.2f}s")
        label = f"{name}, {unit!r} repeated"
        print(f"  {label:45} " + "  ".join(cells))


def f25_part_parameters() -> None:
    """What does reading a part header's parameters cost, and which method do all readers ask?"""
    _banner("F25", "a part header's parameters")
    from email.message import Message

    for count in (250_000, 500_000, 1_000_000):
        raw = b"Content-Type: text/plain" + b";" * count + b"\r\n\r\nx"
        part = message_from_bytes(raw, policy=email.policy.compat32)
        start = time.perf_counter()
        part.get_param("charset")
        read = time.perf_counter() - start
        start = time.perf_counter()
        message_from_bytes(
            raw.replace(b"text/plain", b"multipart/mixed"), policy=email.policy.compat32
        )
        parsed = time.perf_counter() - start
        print(f"  {count:>9} ';'  get_param {read:.2f}s   parsing it as multipart {parsed:.2f}s")

    class Counting(Message):
        asked = 0

        def _get_params_preserve(self, failobj, header):  # type: ignore[no-untyped-def]
            Counting.asked += 1
            return super()._get_params_preserve(failobj, header)

    raw = (
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b'Content-Disposition: attachment; filename="a.pdf"\r\n\r\nx'
    )
    policy = email.policy.compat32.clone(message_factory=Counting)
    part = message_from_bytes(raw, policy=policy)
    for reader in (
        "get_param",
        "get_params",
        "get_boundary",
        "get_filename",
        "get_content_charset",
    ):
        before = Counting.asked
        method = getattr(part, reader)
        method("charset") if reader == "get_param" else method()
        print(f"  {reader:20} asks _get_params_preserve {Counting.asked - before} time(s)")


def f26_writing_a_message_out_again() -> None:
    """Does a bare CR end a delimiter line, and what does writing a message out again cost?"""
    _banner("F26", "a bare CR, and a message written out again")
    raw = (
        b'Content-Type: multipart/mixed; boundary="b"\n\n'
        b"--b\rContent-Type: text/plain\n\none\n--b\rContent-Type: text/plain\n\ntwo\n--b--\r"
    )
    parts = message_from_bytes(raw, policy=email.policy.compat32).get_payload()
    print(f"  delimiters ending in a bare CR: {len(parts)} parts")
    smtp, as_stored = email.policy.SMTP, email.policy.SMTP.clone(refold_source="none")

    def written(header: bytes, policy: email.policy.Policy) -> tuple[bytes, float]:
        message = message_from_bytes(
            header + b"\nSubject: s\n\nbody\n", policy=email.policy.compat32
        )
        buffer = BytesIO()
        start = time.perf_counter()
        BytesGenerator(buffer, policy=policy).flatten(message)
        return buffer.getvalue(), time.perf_counter() - start

    for size in (4_000, 8_000, 16_000):
        header = b"Cc: " + b"." * size
        _, refolded = written(header, smtp)
        _, stored = written(header, as_stored)
        print(f"  Cc of {size:>6} periods: refolded {refolded:.2f}s, as stored {stored:.3f}s")
    for label, header in (
        ("short lines", b"X-Short: one two"),
        ("a folded header", b"X-F: one\n two"),
        ("a line of 200 characters", b"X-Long: " + b"word " * 40),
    ):
        a, _ = written(header, smtp)
        b, _ = written(header, as_stored)
        print(f"  {label:26} refolded and as stored {'identical' if a == b else 'differ'}")


def f27_the_parse_floor() -> None:
    """What does one parse cost when the lines are many and short?"""
    _banner("F27", "the cost of one parse, by line length")
    shapes = {
        "a body of empty lines": lambda size: b"Subject: s\r\n\r\n" + b"\r\n" * (size // 2),
        "a body of 76-character lines (control)": lambda size: (
            b"Subject: s\r\n\r\n" + (b"a" * 76 + b"\r\n") * (size // 78)
        ),
        "header lines of 'X-A: a'": lambda size: b"X-A: a\r\n" * (size // 8) + b"\r\nbody",
    }
    for label, make in shapes.items():
        cells = []
        for megabytes in (1, 2, 4):
            raw = make(megabytes * 1_000_000)
            start = time.perf_counter()
            BytesParser(policy=email.policy.compat32).parsebytes(raw)
            elapsed = time.perf_counter() - start
            cells.append(f"{megabytes} MB {elapsed:.2f}s")
        print(f"  {label:40} " + "  ".join(cells))


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
    f18_the_registry_does_not_unfold()
    f19_an_address_written_inside_quotes()
    f21_a_filename_read_by_three_grammars()
    f23_html_parser_fed_in_pieces()
    f24_the_header_parser_cost()
    f25_part_parameters()
    f26_writing_a_message_out_again()
    f27_the_parse_floor()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
