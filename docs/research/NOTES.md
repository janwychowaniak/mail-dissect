# CPython `email` / `html.parser` — research notes

Probed **2026-09-17** on **CPython 3.13.12** with
[`probes/email_stdlib.py`](probes/email_stdlib.py). Every finding below is printed by one
function in that script; re-run it against a newer interpreter to see whether a finding
still holds. The probes are offline, read-only and stdlib-only.

These notes feed [`../SPEC.md`](../SPEC.md). Where something is a **decision**, the spec
wins; this file records only **what the standard library actually does**.

---

## TL;DR for the spec

- Re-serialising a parsed message reproduces the input **only when the input was already
  canonical**. Every malformed shape this service exists to handle is silently normalised,
  and two of them lose headers outright — by two different mechanisms, one of which raises no
  defect at all. Hence `[D12]`: the `eml` artifact carries original bytes. (F1, F1b)
- A `message/rfc822` part carrying `Content-Transfer-Encoding: base64` is parsed into a
  bogus `text/plain` child under **both** policies. The tree is wrong and the only signal is
  a defect that also fires for benign reasons. Hence the explicit recursive-decode rule. (F2)
- `policy.default` costs ~10× `compat32` for the same tree, and the cost is per part. Hence
  `[D11]` (tree from `compat32`) and `[D13]` (part limits established before parsing). (F3)
- One 8-bit byte in a header can make the response unserialisable on Starlette's exact JSON
  path — but not on `json.dumps`' default path, which is why a careless probe clears it.
  Hence `[D20]`. (F5)
- The stdlib almost never raises on broken transfer encodings; `attachment_unreadable` and
  `malformed_mime` therefore need definitions of our own, not a defect check. (F8)
- `html.parser` survives every hostile HTML shape tried, sub-second, without raising. Hence
  `[D15]` (no C extension for the one input class guaranteed to be hostile). (F10)

---

## F1 — re-serialisation is byte-identical only for already-canonical messages

`BytesGenerator(policy=SMTP).flatten()` on a parsed nested message reproduces the input
exactly for a well-formed CRLF message — so a probe that tests only the happy path will
report "identical" and clear the whole question wrongly. The divergences appear precisely on
malformed input:

| Input shape | Re-serialised result |
| --- | --- |
| already canonical, tab continuation | identical |
| LF-only line endings | normalised to CRLF |
| header longer than 78 chars | refolded onto continuation lines |
| `From:a@example.com` (no space after colon) | space inserted |
| 8-bit bytes in a header | re-encoded as `=?unknown-8bit?q?...?=` |
| message with headers but no body | a blank line appended |
| `From : a@example.com` as the only header | rebuilt as `\r\nbody` — the line is gone |
| `X-Broken : yes` between two valid headers | `From: …` + blank line + the rest as body |

The last two rows are both losses, and they are two **different** mechanisms (F1b), so neither
generalises to "a malformed header disappears". In the first, one line is silently reclassified
and the rebuilt message has no headers at all; in the second, the header block ends early and
the `Subject:` that followed is no longer a header in the rebuilt message. Either way a
`sha256` taken from the reconstruction identifies something the sender never sent, and nothing
in the response would say so.

## F1b — a space before the colon: two mechanisms, one of them without a defect

`email.feedparser.headerRE` is `^(From |[\041-\071\073-\176]*:|[\t ])`. The middle alternative
excludes the space character before the colon, so `X-Broken : yes` is not a header line; but the
**first alternative matches any line starting with `From `**, which is the Unix mbox envelope
rule.

| Input | Headers parsed | `get_unixfrom()` | Defects | Payload |
| --- | --- | --- | --- | --- |
| `From : a@example.com` alone | **none** | `'From : a@example.com'` | **none** | `'body'` |
| `X-Broken : yes` among valid headers | `From` only | `None` | `MissingHeaderBodySeparatorDefect` | `'X-Broken : yes\r\nSubject: s\r\n\r\nbody'` |

The first row is the dangerous one: a line a human reads as a `From` header produces a message
with **zero headers and no defect at all** — nothing to notice. It also has a contract
consequence: the `UNPARSABLE` boundary (SPEC §15) must be decided on the raw bytes, not on
"the standard library returned no headers", because a genuine mbox export legitimately begins
with an envelope line followed by real headers.

Also: `get_payload(decode=True)` on a `message/rfc822` part returns `None`, because its
payload is a list of `Message` objects — there is no stdlib call that hands back the nested
message's bytes.

## F2 — a transport-encoded nested message is parsed into a bogus text part

For a `message/rfc822` part with `Content-Transfer-Encoding: base64`, both `compat32` and
`policy.default` produce the same wrong tree:

```
types   = ['multipart/mixed', 'message/rfc822', 'text/plain']
defects = ['MissingHeaderBodySeparatorDefect']
```

The `text/plain` child holds the base64 text, not the inner message. RFC 2045 §6.4 does not
allow this encoding for `message/*`, but mail gateways emit it anyway. An implementation
that trusts the tree sees an ordinary text part, builds a wrong `messages[]`, and reports
nothing — the defect it does raise also fires for benign malformations, so it cannot be used
as the trigger on its own.

## F3 — `policy.default` costs ~10× `compat32`, per part

| Parts | Size | `compat32` parse | `policy.default` parse | `walk()` |
| --- | --- | --- | --- | --- |
| 5 000 | 0.2 MB | 0.17 s | 2.46 s | 0.00 s |
| 50 000 | 1.9 MB | 2.20 s | 22.75 s | 0.03 s |

The cost is eager per-part header parsing, not tree building — `walk()` itself is free.
Extrapolated to `MAX_MESSAGE_BYTES` (50 MB) of small parts, `policy.default` alone exceeds
`DISSECT_TIMEOUT_SECONDS`. `compat32` is affordable, but neither policy can enforce
`MAX_MIME_PARTS` before doing the work: the limit is only observable once the tree exists.

## F4 — filename extraction needs `policy.default`, and sanitising is ours

| Header | `compat32` | `policy.default` |
| --- | --- | --- |
| `filename*=UTF-8''%E2%82%AC.txt` | `'€.txt'` | `'€.txt'` |
| `filename*0="long-"; filename*1="name.txt"` | `'long-name.txt'` | `'long-name.txt'` |
| `filename="=?utf-8?q?caf=C3=A9.txt?="` | `'=?utf-8?q?caf=C3=A9.txt?='` | `'café.txt'` |
| `filename="../../etc/passwd"` | `'../../etc/passwd'` | `'../../etc/passwd'` |

Both policies handle RFC 2231 on 3.13. Only `policy.default` decodes RFC 2047 encoded-words
inside a filename — non-standard, but common enough to matter. **Neither** strips path
components: traversal defence is the service's job, never the parser's.

## F5 — a lone surrogate is a guaranteed 500, but only on the real JSON path

`To: \xe9v@x.example` parsed under `policy.default` yields `addr_spec == '\udce9v@x.example'`
— a lone surrogate produced by the stdlib's `surrogateescape` handling of 8-bit header bytes.

```
json.dumps(value)                      -> ok        (ensure_ascii=True escapes it)
json.dumps(value, ensure_ascii=False)  -> UnicodeEncodeError: surrogates not allowed
```

Starlette's `JSONResponse.render()` uses `ensure_ascii=False`, so the response raises inside
the framework and the client gets a 500 from five bytes of input. Scrubbing with
`encode("utf-8", "replace")` fixes it and **changes the string** (`'?v@x.example'`), which is
why `[D20]` requires the change to be reported as `encoding_fallback` rather than performed
silently.

## F6 — the header registry does not cover every address header the spec names

| Header | Registry class | `.addresses` |
| --- | --- | --- |
| `from`, `to`, `cc`, `bcc`, `reply-to`, `sender` | `*AddressHeader` | yes |
| `resent-from`, `resent-to`, `resent-cc`, `resent-sender` | `*AddressHeader` | yes |
| **`return-path`** | `UnstructuredHeader` | **no** |
| **`resent-reply-to`** | `UnstructuredHeader` | **no** |

Both missing headers are in the spec's address set, so `HeaderRegistry.map_to_type()` must
remap them before use; reading `.addresses` off the default registry raises `AttributeError`.

## F7 — use the registry for RFC 2047, never `make_header`

| Input | `make_header(decode_header(v))` | `HeaderRegistry` |
| --- | --- | --- |
| `=?utf-8?q?caf=C3=A9?=` | `'café'` | `'café'` |
| `=?bogus-charset?Q?x?=` | **`LookupError`** | `'x'` |
| `=?utf-8?b?not-valid-base64!!?=` | **`UnicodeDecodeError`** | mojibake, no exception |
| `plain ascii` | `'plain ascii'` | `'plain ascii'` |

The legacy path raises on input a hostile sender fully controls. The registry never raises;
for undecodable bytes it returns replacement characters, which is the correct outcome here —
the material is reported as it decoded, with `encoding_fallback` to say so.

## F8 — broken encodings and a garbage `Content-Type` are nearly silent

| Case | Parsed type | `get_payload(decode=True)` | Defects |
| --- | --- | --- | --- |
| base64, length ≡ 1 (mod 4) | `text/plain` | `b'QUJDR'` | `InvalidBase64LengthDefect` |
| base64, illegal characters | `text/plain` | `b''` | `InvalidBase64CharactersDefect` |
| quoted-printable cut mid-sequence | `text/plain` | `b'abc'` | **none** |
| `Content-Type: ;;;garbage` | `text/plain` | `b'body\r\n'` | **none** |

Nothing raises. Two of the four cases produce no defect at all, and a garbage content type
silently becomes `text/plain` — so `malformed_mime` must come from comparing the raw header
against what was parsed, and `attachment_unreadable` from our own decoder reporting that the
byte stream cannot be reconstructed, not from the presence of a defect.

## F10 — `html.parser` survives hostile HTML

| Input | Time | Result |
| --- | --- | --- |
| 500 000 `<` characters | 0.78 s | no exception, all text |
| unterminated comment, 100 kB | 0.00 s | no exception |
| 50 000-deep `<div>` nesting | 0.28 s | no exception, 50 000 start tags |
| 20 000 attributes on one tag | 0.07 s | no exception |
| NUL bytes in text and tags | 0.00 s | no exception |
| unclosed attribute quote | 0.00 s | no exception, tag never emitted |

No exception, no pathological time, and behaviour that depends only on CPython's version —
not on a C library's tree-repair heuristics, which would be a determinism hazard of exactly
the species `[D8]` keeps out of the registries.

---

## Open, to be probed in stage 1 (needs the project's dependencies installed)

- **Starlette multipart limits.** Whether a non-file `eml` part is capped and text-decoded
  while a file part spools unbounded, on the exact Starlette version we pin. Decides how
  `routes.py` reads the form — see `[R6]`.
- **`idna` strictness.** Which hosts `idna.encode(uts46=True)` rejects (`a_b.example`,
  `-bad-.example`, over-long labels) and what the fallback must be for `host_punycode`.
- **Gotenberg screenshot route.** Field names, asset resolution and the response content type
  against a pinned `gotenberg/gotenberg` image — see `[R5]`; captured request/response will
  be committed next to these notes.
