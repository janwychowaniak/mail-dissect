# Research notes — CPython `email`, the dependencies, the tools

F1–F10 were probed **2026-09-17** and F17 **2026-09-23**, on **CPython 3.13.12** with
[`probes/email_stdlib.py`](probes/email_stdlib.py), which needs nothing but the standard
library; F11–F12 on **2026-09-23** with [`probes/dependencies.py`](probes/dependencies.py)
against the versions in `uv.lock`. Each of them is printed by one function in its script; re-run
the script against a newer interpreter or dependency to see whether a finding still holds. Both
scripts are offline and read-only. F13 to F16 each say how they were measured.

These notes feed [`../SPEC.md`](../SPEC.md). Where something is a **decision**, the spec
wins; this file records only **what the standard library, the dependencies and the tools
actually do**.

Finding numbers are identifiers: code, tests and commit messages cite them, so a number is
never reassigned. There is no F9. A finding that turns out wrong is corrected under its own
number, as F15 was.

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
- Under `compat32` a header value holding an 8-bit byte is an `email.header.Header`, not a
  string, while F5 was measured under `policy.default`. Hence `COMPAT32_TEXT`, and the count of
  what the registry replaced silently behind `encoding_fallback`. (F17)

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

## F11 — the framework's form handling caps a text field and picks its codec by content

Probed on Starlette **1.6.0** with python-multipart **0.0.32**, which `request.form()` needs
and `uv.lock` does not contain: the service never calls it, so the probe installs it on the
side.

| `eml` part | `request.form()["eml"]` |
| --- | --- |
| field, ASCII (control) | `str`; encoding it back gives the input under UTF-8 and latin-1 alike |
| field, valid UTF-8 | `str`; only UTF-8 gives the input back |
| field, one 8-bit byte | `str`; only latin-1 gives the input back |
| field, valid UTF-8 plus one 8-bit byte | `str`; only latin-1 gives the input back |
| field, 2 MB | **400** `Part exceeded maximum size of 1024KB.` |
| file part (`filename=`), 3 MB of 8-bit bytes | bytes, identical |

A part without `filename=` is decoded as UTF-8 when it can be and **silently as latin-1 when it
cannot**, so the codec is chosen by the content, and one stray byte anywhere switches the whole
field. The decoding is not reversible: `Subject: café` in UTF-8 and `Subject: caf\xe9` arrive as
**the same string**. Two different messages, one value, and no hash taken from it identifies
what was sent. The cap is per field, not per request: a message just over 1 MB sent as a field is
refused, while the same bytes sent as a file go through untouched.

Hence the form is read by hand (SPEC §4, `src/mail_dissect/intake.py`), so that a client
posting the message as a plain field gets the same bytes, hashes and result as one posting it as
a file or raw.

## F12 — `idna` refuses hosts that a message can contain

Probed on idna **3.20**.

| Host | `idna.encode(host, uts46=True, transitional=False)` |
| --- | --- |
| `bücher.example` (control) | `xn--bcher-kva.example` |
| `a_b.example` | `InvalidCodepoint`: U+005F not allowed |
| `ü_b.example` | `InvalidCodepoint`: U+005F not allowed |
| `-bad-.example` | `IDNAError`: label must not start or end with a hyphen |
| a 64-character label, ASCII or not | `IDNAError`: label too long |

`idna.decode` returns `bücher.example` for `xn--bcher-kva.example` and refuses an A-label that
is not valid punycode (`xn--zz.example`: `Invalid A-label`).

Every refusal is an IDNA2008 rule applied correctly, and every refused host is one that a
message can carry and a hostile one will. Letting the exception decide would drop the host from
the result, which hides a fact about the message because the fact is malformed. Hence
`canonical_host` in `src/mail_dissect/urls.py`: an ASCII host goes through `idna` only when it
has an `xn--` label, so the refusals above never reach it; a refused non-ASCII host falls back
to its lowercased original and has no `host_punycode`; and an `xn--` host that does not decode
keeps its A-label and has no Unicode form.

## F13 — the extension registry does not know the script extensions

Measured against a 64-item probe of extensions that occur in mail, `mime-db@1.54.0` (1 239
extensions) covers 49 and misses 15 — and the misses are almost exactly the script and
executable formats:

```
missing: cmd scr pif vbs vbe jse wsf wsh hta ps1 psm1 reg accdb z tgz
```

Apache Tika's `tika-mimetypes.xml` (1 299 extensions, 414 of them not in mime-db) covers
`cmd`, `vbs`, `accdb`, `z` and `tgz` of that list and misses the other ten. Neither registry
knows `scr`, `pif`, `hta` or `ps1`, because none of them has a registered media type.

The consequence under SPEC §11.2 is narrow but real: a filename **written in the body text**
whose extension is in neither registry produces no `filename` candidate, and if its final
label is not a public suffix either, it produces nothing at all — `payload.scr` is invisible
in `observables[]`. Attachment filenames are unaffected: they are a fact in `attachments[]`,
never a candidate (SPEC §11.2), so the gap only touches filenames the message talks about.

This is a property of the registry, not a defect in the grammar. Closing it would mean adding
a second registry, not a list of our own — which is a decision, not an implementation detail.

## F14 — the `domain`/`filename` collision covers ordinary mail, not corner cases

Two registries genuinely claim the same string whenever a public suffix is also a file
extension. Measured against the shipped snapshots:

**60 of the 1441 single-label ICANN suffixes are also mime-db extensions** — 4.2%, but the
4.2% contains `com` (`application/x-msdownload`) and `org` (`text/x-org`), along with `zip`,
`mov`, `md`, `sh`, `xyz`, `ai`, `me`, `cc` and `pl`. `net`, `info`, `io`, `dev` and `app` do
not collide.

Every `.com` and `.org` domain in a message therefore carries a `filename` twin, both
flagged. Those are the two commonest domains in mail, so this is the ordinary case rather than
a corner one — the `raport.zip` example that the rule is usually explained with is the rarer
half of it.

So a consumer reading `observables[]` without filtering on `ambiguous` sees close to twice
the list they expected and will read it as a defect. It is not: the rule is working, and
subtracting these extensions from the registry would be a worse cure than the disease — `com`
really is an executable extension (`command.com`) and `pl` really is a Perl script, so
removing them blinds the channel exactly where it earns its place. The flag is the answer, and
dropping one side of a collision costs the consumer a single condition.

## F15 — the two tools, verified against real images rather than assumed

Probed **2026-09-18** against `apache/tika:3.2.3.0` and `gotenberg/gotenberg:8.37.0`, the
versions pinned in `compose.yml`.

**Tika's contract is exactly what the specification says.** `PUT /tika` with the raw bytes,
`Accept: text/plain` and the attachment's `Content-Type` returns the extracted text as the
body. A 617-byte hand-built PDF carrying one line came back with that line, verbatim.

**Gotenberg's screenshot route works, and `--chromium-deny-list=.*` breaks it.** Every render
under that flag answers **403 Forbidden**:

```
HTML screenshot: screenshot: filter URL:
'file:///tmp/…/….html' matches the expression from the denied list
```

The reason is narrow and worth stating precisely: **Gotenberg serves the uploaded page from a
`file:///tmp/…` URL of its own**, so a rule that denies everything denies the document it was
asked to render. It is not that scoping `file:` is infeasible — the tool's own default deny
list is `^file:(?!//\/tmp/).*`, a negative lookahead expressing exactly "deny `file:` outside
/tmp". An earlier version of this finding claimed the engine had no lookahead and that such a
rule could not be written; that was wrong, and the wrong version invited a looser
configuration.

**The allow-list is what stops a beacon, and it does so without any network isolation.**
Measured with a positive control — the same renderer, the same page, only the allow-list
differing — against a listener in the same container network:

| Renderer configuration | Requests reaching the listener |
| --- | --- |
| `--chromium-allow-list='^file:///.*\|^http://beacon-srv:8099/.*'` | **2** (`/img`, `/iframe`) |
| `--chromium-allow-list='^file:///.*'` | **0** |
| `--chromium-allow-list='^file:///tmp/.*'` | **0** |

The path was proven reachable first (`curl` from inside the renderer container reached the
listener), so the zero is a block rather than a broken experiment. This is a stronger property
than "the network has no route out": a deployment that copies the example without isolating
the network is still protected from a message beaconing to its sender.

**The allow-list does not switch off the built-in deny-list.** A page containing
`<iframe src="file:///etc/hostname">` renders to an image **byte-identical** to the same page
pointing at a file that does not exist, under both `^file:///.*` and `^file:///tmp/.*`.

`^file:///tmp/.*` is therefore the better example: it costs nothing — ordinary renders,
embedded assets and the beacon block all behave identically — and it states the intention in
our own configuration instead of inheriting it from somebody else's default.

Two smaller observations: Gotenberg's own Chromium reaches for `accounts.google.com` and
`android.clients.google.com` at startup, which the allow-list blocks and the logs record; and
a tag we had pinned, `gotenberg/gotenberg:8.24.2`, does not exist at all — it was written from
memory, and pulling it is what proved that.

**The request shape is held by `tests/test_live_tools.py`, not by a capture.** A captured
request and response were once promised here. They were never committed, and the live tests do
the job better: a capture records one exchange, while a test repeats it against whichever image
a maintainer runs it on. The pinned image answers the request `tools.py` sends (the page as
`index.html` in the `files` field) with a PNG, both by magic bytes and by `image/png`. **Asset
resolution is only half held:** `test_an_embedded_image_reaches_the_renderer` proves that the
renderer accepts a `cid:` asset uploaded alongside the page, not that the image appears in the
render.

## F16 — moving images to a host that cannot pull

Probed **2026-09-18** on Docker **29.1.3**, storage driver **overlay2** (the classic image
store, not the containerd snapshotter — the distinction matters for the last row).

| Saved as | After `docker load` |
| --- | --- |
| `docker save <image id>` | `RepoTags=[]`, `RepoDigests=[]` |
| `docker save <repo:tag>` | `RepoTags=[repo:tag]`, `RepoDigests=[]` |

**An archive saved by image ID loads with no tags**, and an untagged image is invisible to
`docker compose`: it falls through to a registry pull, which is exactly what the target host
cannot do. The failure appears only on the machine that cannot reach a registry, which is the
worst place to discover it.

**`RepoDigests` does not survive the round trip**, for an image that had been pulled from a
registry. Measured twice and independently — here on `ghcr.io/janwychowaniak/mail-dissect`,
and separately by the maintainer on a freshly pulled `busybox:1.37` — with the same result on
the same engine and store.

The control is the whole finding. A `load` over an image that is still present is a no-op and
leaves the existing metadata in place, so the measurement reads as "the digest survived" while
nothing has happened at all. The first attempt at this measurement produced exactly that false
positive, and its cause is worth naming: the `docker rmi` in the preparation step **failed**,
because two stopped containers still referenced the image, and its error was silenced and its
exit status ignored. Verify between steps that the removal actually removed something
(`docker image inspect` must fail) before trusting the result.

Whether the containerd image store behaves differently is untested. The practical answer does
not depend on it: compare the **checksum of the archive** on both sides, since that is the
artifact both sides actually hold.

## F17 — `compat32` hands an 8-bit header value out as a `Header`, not a string

| Policy | `msg["X-Ok"]`, ASCII (control) | `msg["Subject"]`, `msg["To"]`, one byte `\xe9` |
| --- | --- | --- |
| `compat32` | `str` | **`email.header.Header`**, not a `str` |
| `policy.default` | a header object that is a `str` | a header object that is a `str` |

`raw_items()` holds the value as a string with the byte escaped to a lone surrogate
(`'caf\udce9'`); only fetching wraps it, because `Compat32.header_fetch_parse` turns any value
with a surrogate in it into a `Header`.

F5 was measured under `policy.default`, where the value is a string and the lone surrogate
reaches the JSON encoder, and `[D20]` was decided against that. The tree is read under
`compat32` `[D11]`, where the value never became that string: it arrived as a `Header`, reached
`.strip()` and a regular expression, and one byte above 0x7F in any header of a message was a
500 before the encoder was ever involved. The decision was right; the measurement it rested on
was taken on the other policy. Hence `COMPAT32_TEXT` in `src/mail_dissect/headers.py`: the
fetch returns the stored string, and parsing stays `compat32`'s own.

Two things read that string afterwards, and neither says what it did. The header registry reads
the escaped bytes as UTF-8 and puts U+FFFD where that fails, without a defect:

| `HeaderRegistry()("subject", value)` | Result | `defects` |
| --- | --- | --- |
| `'caf\udce9'`, an 8-bit byte | `'caf\ufffd'` | none |
| `'caf\udcc3\udca9'`, raw UTF-8 | `'café'` | none |
| `'=?utf-8?q?caf=E9?='`, an encoded-word of bad UTF-8 | `'caf\ufffd'` | none |

F7 already said such a replacement is reported as `encoding_fallback`, and nothing raised it;
the substitution is now counted where the headers are read. And `codecs.lookup` refuses a name
it cannot read with a `ValueError` rather than a `LookupError` — `UnicodeEncodeError` for
`'caf\udce9'`, `ValueError` for `'utf\x00'`, against `LookupError` for `'x-nonsense'` — so a
`charset=` parameter carrying an 8-bit byte or a NUL fell out of the ladder of SPEC §7.2.

A filename declares a charset in a third way, RFC 2231, and `get_filename()` takes both kinds
of failure silently too: `filename*=utf-8''caf%E9.txt` comes back as `'caf\ufffd.txt'`, and
`filename*=x-no-such-charset''caf%E9.txt` as `'café.txt'`, read in some other charset, both
without a defect. `email.utils.collapse_rfc2231_value` decodes with `replace` and falls back on
a charset it cannot find, so whether the declaration was taken has to be checked separately.

The declared type also travels on, as the `Content-Type` of the request to the text extractor.
Measured by hand with `httpx` 0.28.1 against `apache/tika:3.2.3.0`: a type with a byte above
0x7F in it, surrogate or valid UTF-8 alike, raises `UnicodeEncodeError` before anything is sent,
and that is not an `httpx.HTTPError`, so it escaped the client's handling as a 500; a type
with a control character is sent and answered **400**, which the client reports as the tool
being `down`. The control, `application/pdf`, reached the tool and was answered on its merits.

