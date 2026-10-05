# Research notes — CPython `email`, the dependencies, the tools

F1–F10 were probed **2026-09-17**, F17 **2026-09-23**, F18 and F19 **2026-09-30**, on
**CPython 3.13.12** with
[`probes/email_stdlib.py`](probes/email_stdlib.py), which needs nothing but the standard
library; F11–F12 on **2026-09-23** with [`probes/dependencies.py`](probes/dependencies.py)
against the versions in `uv.lock`; F20 on **2026-10-01** with
[`probes/observables.py`](probes/observables.py), which measures the service's own grammars and
was run inside the published 0.4.0 image and on the tree that became 0.5.0; F21 on
**2026-10-03** with `probes/email_stdlib.py`, on 3.13.12 and on 3.13.15 inside the published
0.5.0 image; F22 on **2026-10-05** with [`probes/grammar.py`](probes/grammar.py), on 3.13.12
against the tree of `v0.6.0`; F23 on **2026-10-05** with `probes/email_stdlib.py`, on 3.13.12
and on 3.13.16 inside the published 0.6.0 image. Each of them is printed by one function in its script; re-run the script against a
newer interpreter, dependency or release to see whether a finding still holds. The scripts are
offline and read-only. F13 to F16 each say how they were measured.

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
- `compat32` hands a folded header value out with its line breaks in it, and the header
  registry does not unfold: it raises on an address, keeps the break in an unstructured
  value, and drops the parameters after it. `policy.default` unfolds first, and F7 was
  measured on one-line values. Hence `[D24]`: every value is unfolded where it is fetched.
  (F18)
- An address written inside quotes is, to the parser, a local part with no domain. Reading
  that local part again gives the address — and for the shapes that are not one clean
  address it gives a mailbox **and a defect**, with a mailbox count that differs between
  3.13.12 and 3.13.15. Hence `[D25]` takes a reading only when there is no defect. (F19)
- Every grammar but IPv4 took a period or a hyphen next to a candidate for punctuation; the
  IPv4 one let either of them rule the address out, so an address that ended a sentence was
  never a candidate. Hence `[D26]`: what decides is the character on the far side of the mark.
  (F20)
- A name's encoded-words were decoded by handing the bare name to the parser of
  `Content-Disposition`, which rewrote a `;` and what followed it as a parameter on every
  interpreter, and joined two encoded-words on 3.13.15 only — by a change in `get_phrase` that
  nothing pinned. `policy.default` is no better a rule: it keeps the white space at a segment
  boundary and takes whichever of two forms comes first. Hence `[D27]`: the name is read with
  the grammar of unstructured text, by a rule written as its result. (F21)
- The defanged path of 0.6.0 grows a marker over a fixed set of characters and then demands
  that the whole token be one candidate: a mark in front of the form loses it, a character
  outside the set cuts or distorts it, and a run of markers costs about 150 µs a character.
  Separately, about one unit in ten, repeated into a run with no white space, makes the
  grammar's cost grow faster than linearly. `probes/grammar.py` also holds the comparison every
  change to the grammar in 0.7.0 is held to: zero differences, or each one recorded. (F22)
- `html.parser` fed in pieces reads a document the way it reads it fed at once only where the
  interpreter decides the end of an empty comment without looking ahead: 3.13.16 does, 3.13.12
  does not. The parse of `<!-->` itself moved between the two. Hence the HTML scan is fed once
  and stopped from inside when the deadline passes `[D10]`, never fed in pieces. (F23)

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

What the service reads a name with is neither of these readings: see F21 and `[D27]`.

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

**The image Id does survive the round trip**, measured **2026-10-03**: archives of 0.5.0 and
0.4.0, each saved by its tag on Docker 29.1.3, loaded into an isolated Docker 28.5.2
(`docker:28-dind`) whose store was checked to be empty first — no images, and `inspect` of the
tag failing. Each loaded with its tag and **the same Id as at the source**, and with
`RepoDigests` empty, as above. The control is the other archive: it loaded as the other Id, so
the comparison can tell two images apart. The Id is the digest of the image's configuration,
and the archive carries that file byte for byte (`manifest.json` names it as `Config`); the
registry's digest is a digest of a manifest the archive does not contain.

**The Id identifies bytes, not a recipe.** The same build context built again gave the same Id
with the builder's cache — the same bytes, reused — and a different one with `--no-cache`. So
an Id cannot be reproduced by building; it can only be compared with what was published. Since
0.6.0 the release workflow attaches the archive to the release, and runs this same round trip
on it before it does (`.github/scripts/archive-image.sh`).

Two traps on the way. Copying the archive into `/tmp` of the `dind` container reported success
and left nothing to load, because the container's entrypoint mounts a tmpfs over `/tmp` after
the copy lands beneath it; the archive went in through standard input instead. And a stopped
container does not stop `docker rmi --force`: the image record goes, `inspect` fails, and a
`load` restores it, so a removal has to be checked by `inspect` rather than assumed from a
container that might hold it. A running container does stop it.

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

## F18 — the header registry does not unfold, and `compat32` hands the fold over

| Header as written (`⏎` is CRLF) | `compat32` holds | The registry, given that | The registry, unfolded first |
| --- | --- | --- | --- |
| `From: Alice Example⏎<TAB><alice@example.net>` | `'Alice Example\r\n\t<alice@example.net>'` | **`ValueError`**: address parts cannot contain CR or LF | `'Alice Example <alice@example.net>'` |
| `Subject: =?utf-8?q?exam?=⏎ =?utf-8?q?ple?=` | `'=?utf-8?q?exam?=\r\n =?utf-8?q?ple?='` | `'exam\r\n ple'`, no defect | `'example'` |
| `X-Note: first⏎ second` | `'first\r\n second'` | `'first\r\n second'`, no defect | `'first second'` |
| `Content-Type: text/plain;⏎ charset=utf-8` | `'text/plain;\r\n charset=utf-8'` | `'text/plain;'`, two defects, the parameter gone | `'text/plain; charset="utf-8"'` |
| `X-After-Colon:⏎ value` (the control) | `'value'` | `'value'` | `'value'` |

The last column is also what `policy.default` returns for each of them. It gets there because
unfolding is the policy's step, not the registry's: `EmailPolicy.header_fetch_parse` removes
every line break (`\n|\r\n?`) before its header factory sees the value. `compat32` has no such
step — it stores the value with the breaks in it and hands it out that way — and this service
reads the tree under `compat32` `[D11]` and calls the registry itself (F7). So the step was
nobody's. A value broken straight after its colon is the one fold `compat32` does remove, which
is why the control comes through.

F7 measured the registry on one-line values, and every fixture the tests build is one line to
a header, so nothing folded had reached it. The measurement was true, and it was not about what
`compat32` hands over — the mistake of F17 again, a measurement of the neighbour, made once in
the probe and once in the fixtures.

What that did in the service, measured on 0.2.0 with a folded message and its unfolded twin:

| Folded | 0.2.0 returned | Its unfolded twin |
| --- | --- | --- |
| any address header | one entry of nulls in `addresses`, the raw value undecoded in `headers` | the addresses, decomposed |
| two encoded-words either side of a fold | both decoded, `\r\n` and the white space left between them | joined, as RFC 2047 §6.2 says |
| any other header | the value with `\r\n` in it | the value |
| `Content-Type` | `text/plain;` in `headers`, the tree and the body read correctly | `text/plain; charset="…"` |
| a name cut between two encoded-words | its second half as a candidate in `observables[]` | the name |
| an address header with an encoded-word that does not decode | undecoded, no `encoding_fallback` | U+FFFD and the flag |
| a part's `filename=`, `name=` or `Content-ID`, folded inside the value | the field with `\r\n` in it | the field |
| `Received`, folded inside its timestamp | `received[].timestamp` with `\r\n` in it | the timestamp |
| `Authentication-Results`, folded inside a quoted parameter | that entry of `auth[].params` with `\r\n` in it | the parameter |

The last two rows are the only fields of `received[]` and `auth[]` that take more than one
token. Every other field there is a single token, which white space ends, so a fold could only
fall between fields, and those came out the same either way. This was first recorded as
"`received[]` and `auth[]` came out the same", from a fixture folded between fields and nowhere
else — a measurement of the neighbour, inside the note about one. The timestamp was pointed out
in review, and the parameter turned up when the same question was then asked of `auth[]`.

The MIME tree itself — which parts there are, their types, their charsets and their bodies —
came out the same on every folded message measured: the standard library's own readers of
`Content-Type` cope with a folded value.

Hence the unfolding in `COMPAT32_TEXT.header_fetch_parse`: one place, through which every
header of a message, of a part and of a nested message is fetched, removing the same
characters `policy.default` removes.

**Which headers are structured is the interpreter's map.** `headers{}` returns the registry's
rendering of a structured header and the written value of any other `[D24]`, so the map is part
of what a response depends on:

| Registry class | Headers |
| --- | --- |
| `UniqueAddressHeader` | `from`, `to`, `cc`, `bcc`, `reply-to` — and `return-path`, by F6 |
| `AddressHeader` | `resent-from`, `resent-to`, `resent-cc`, `resent-bcc` — and `resent-reply-to`, by F6 |
| `UniqueSingleAddressHeader`, `SingleAddressHeader` | `sender`, `resent-sender` |
| `UniqueDateHeader`, `DateHeader` | `date`, `orig-date`, `resent-date` |
| `MessageIDHeader`, `ReferencesHeader` | `message-id`, `in-reply-to`, `references` |
| `MIMEVersionHeader`, `ContentTypeHeader`, `ContentTransferEncodingHeader`, `ContentDispositionHeader` | `mime-version`, `content-type`, `content-transfer-encoding`, `content-disposition` |
| `UniqueUnstructuredHeader`, and `UnstructuredHeader` for every other name | `subject`, and the rest |

A Python release that maps a name differently changes what the service returns for that
header without a line of this repository changing. `tests/pins.py` holds the map and the values
of the saved folded messages, and CI runs it inside the built image, on the interpreter that is
published, as well as in the suite.

## F19 — an address written inside quotes, and what reading its local part again gives

`From: "Bob Example <bob@example.net>"` is one quoted string, and by the grammar a quoted
string in that position is a local part. The registry returns one address for it with the whole
string as its local part and no domain — `addr_spec` `'"Bob Example <bob@example.net>"'`,
`domain` `''` — and records no defect on the header as a whole. Handing that local part to the
same registry once more:

| Written between the quotes | Mailboxes | Defects | One clean mailbox |
| --- | --- | --- | --- |
| `Bob Example <bob@example.net>` | 1: `bob@example.net`, name `Bob Example` | none | **yes** |
| `bob@example.net` | 1: `bob@example.net` | none | **yes** |
| `Bob Example <bob@example.net> via list` | 1 on 3.13.12, **2 on 3.13.15** (the second is `<>`) | `InvalidHeaderDefect` | no |
| `Bob <bob@example.net> <eve@example.org>` | 1 on 3.13.12, **2 on 3.13.15** (the second is `<>`) | `InvalidHeaderDefect`, `ObsoleteHeaderDefect` | no |
| `bob@example.net, eve@example.org` | 2 | none | no |
| `Bob Example` | 1, with no domain | `InvalidHeaderDefect` | no |

Two things follow. **The mailbox count alone is not a criterion**: on 3.13.12 the third and
fourth rows hold exactly one mailbox with a domain, and taking it would drop the text after the
address in one and the second address in the other, silently. The defect is what says the
parser did not account for everything it was given — and it is there on both interpreters,
while the count is not. **And the count moves within 3.13**: the same input is one mailbox on
the interpreter the suite ran on and two on the one in the image built the same day. The
verdict of `[D25]` is the same on both for every shape measured, because a second mailbox and
a defect each rule the reading out on their own; `tests/pins.py` pins the verdicts and runs on
both.

A mailbox with no domain always came with a defect here, so "has a domain" never decided a case
by itself. It stays in the rule as the thing being asked for, and is tested against a stand-in
parser, since this one cannot be made to produce the case.

One shape is not a quoted string and is read the same way: `"bob@example.net".x`, a quoted
word and an atom joined by a dot, which the parser reports as the single local part
`bob@example.net.x`. Read again, that is the address `bob@example.net.x`. And an entry that has
a domain is not read again at all: `"first@example.org" <second@example.net>` is the address
`second@example.net` with the display name `first@example.org`, as written.

## F20 — a period or a hyphen next to a candidate: every grammar took it for punctuation but IPv4

Measured on the service itself, not on a dependency: the text goes to the collector, and the
table is what comes back. The "to 0.4.0" columns were taken inside the published images, and the
five of them, 0.1.0 to 0.4.0, print the same lines.

| Written | domain | url | email | IPv6 | hash | IPv4, to 0.4.0 | IPv4, from 0.5.0 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| candidate, then a period | returned | returned | returned | returned | returned | **nothing** | returned |
| candidate, then a hyphen | returned | returned, hyphen included | returned | returned | returned | **nothing** | returned |
| a period, then the candidate | returned | returned | returned | nothing | returned | **nothing** | returned |
| a hyphen, then the candidate | returned | returned | returned | returned | returned | **nothing** | returned |

The IPv4 alternative carried `(?<![\w.-])` in front and `(?![\w.-])` behind. They are what keeps
four numbers out of a longer token, and they did it by refusing the address whenever a period
or a hyphen touched it — so `192.0.2.1.` at the end of a sentence was refused by the same test
that refuses `1.2.3.4.5`. Nothing flagged it: the candidate was gone before `ipaddress` saw it.

What tells the two apart is the character on the far side of the mark, and `[D26]` asks for
that and nothing else:

| Written | To 0.4.0 | From 0.5.0 |
| --- | --- | --- |
| `192.0.2.1.` then a space, the end of the text, `)`, `..` | nothing | the address |
| `192.0.2.1-` then a space or a line break | nothing | the address |
| `.192.0.2.1`, `...192.0.2.1`, `-192.0.2.1` | nothing | the address |
| `192.0.2.1.example.net`, `192.0.2.1-static.example.net` | the host name, as a `domain` | the same |
| `192.0.2.1.Next` | `192.0.2.1.next`, as a `domain` (sentence noise, SPEC §11.3) | the same |
| `192.0.2.1.5`, `192.0.2.1-rc1` | nothing | nothing |
| `word-192.0.2.1`, `end.192.0.2.1`, and the same after `é` or `_` | nothing | nothing |

The far side is one character, and a second mark there is not a label character. That is what
lets `a--b` and `a...b` return both ends, and it has a price: `192.0.2.1--static.example.net`
was one host name to the domain grammar up to 0.4.0 and is the address and `static.example.net`
from 0.5.0, as is `192.0.2.1-` at the end of a line with `static.example.net` on the next one,
where only the tail came back before.

`\w` is what "label character" means here, and in a `str` pattern it is a letter, a digit or an
underscore **in any script**: `é-192.0.2.1` is ruled out the way `word-192.0.2.1` is. The
alternative for a domain or a file name is ASCII-only, so after `é` or `_` nothing else would
have swallowed the token — the lookbehind is what holds there, not an accident of the order.

**Refused as an address, the same text could come back as something else.** Two of the 256
last numbers an address can have are file extensions in the registry, `123` and `210`. Up to
0.4.0 `192.0.2.123.` was refused by the IPv4 alternative, fell through to the one for a domain
or a file name, and was returned as the `filename` `192.0.2.123` — and so was `192.0.2.123-`,
`-192.0.2.123` and `.192.0.2.123`. From 0.5.0 each of them is the address, as `192.0.2.123`
with a space on both sides always was: the alternative for an address comes first. Five numbers
ending in such an extension, `192.0.2.1.123`, are a file name before and after, and so is a
whole range written `a-b` whose right end ends in one.

**A range** is two addresses and a relation between them, and the service returns addresses.
What it must not do is return one end of two:

| Written | To 0.4.0 | From 0.5.0 |
| --- | --- | --- |
| `a - b`, `a–b` (en dash) | both ends | both ends |
| `a-b` | neither | neither |
| `a- b` | the right end only | both ends |
| `a -b` | the left end only | both ends |
| `a...b`, `a..b` | neither | both ends |
| `a:80-b:80` | the left end only | the left end only |
| `a/32-b/32` | one `url` and the left end | the same |
| `::ffff:a-b` | the left end, as IPv6 | the same |

The middle rows are why the rule is the same on both sides of the address. Letting a period
after the address through while a period before it still ruled it out would have turned the
silence of `a...b` into "the left end only". The last three rows were half a range before and
still are, and `[D26]` records them as left where they were. In the first two the right end
lies inside a longer match of another alternative — a token that starts at the port, a URL that
starts at the left end — and in the third the left end is returned by the IPv6 grammar, which
does not look at what follows it.

**The defanged path loses a candidate that follows a hyphen or a period**, in every grammar:

| Written | Returned |
| --- | --- |
| `host[.]example[.]net`, `192[.]0[.]2[.]1` after a space | the candidate, `defanged` |
| `192[.]0[.]2[.]1.` | the address, `defanged` — the period after it is trimmed |
| `-host[.]example[.]net`, `.host[.]example[.]net` | nothing |
| `-hxxp://example[.]net/x`, `-user[at]example[.]net`, `-192[.]0[.]2[.]1` | nothing |

A defanged form is found by growing its marker outwards to the token that contains it, and a
hyphen or a period in front is taken along as part of that token; re-armed, the token no longer
reads as anything. The same text without the defanging is returned. This is a different
mechanism from the one above and `[D26]` does not touch it: it is a known defect, listed in
`CHANGELOG.md` and stated by `tests/test_known_defects.py`. F22 measures the mechanism on its
own, and what else it cuts, distorts and costs.

## F21 — a filename read by three grammars, and which one moved

Probed with `f21_a_filename_read_by_three_grammars` in `probes/email_stdlib.py` on 3.13.12 and
on 3.13.15 inside the published 0.5.0 image, and through the service itself over HTTP on both,
with the same thirty shapes of name.

Until 0.6.0 the service decoded the encoded-words of a name by handing the bare name —
`get_filename()` under `compat32`, which decodes none — to the header registry as the value of
`Content-Disposition`. That grammar expects a disposition type first: it fails at the first `=`
of the first encoded-word, and its recovery path (`_find_mime_parameters`) reads the rest
through `get_phrase`, the grammar of a display name.

| The bare name | as `Content-Disposition`, 3.13.12 | as `Content-Disposition`, 3.13.15 | as unstructured text, both |
| --- | --- | --- | --- |
| two encoded-words, `naïve-no` and `tes.txt` | `naïve-no tes.txt` | `naïve-notes.txt` | `naïve-notes.txt` |
| two encoded-words split inside the extension | `notes.t xt` | `notes.txt` | `notes.txt` |
| an encoded-word, then `;v2.pdf` | `résumé; v2.pdf` | `résumé; v2.pdf` | `résumé;v2.pdf` |
| an encoded-word, then `;x=y.pdf` | `résumé; x="y.pdf"` | `résumé; x="y.pdf"` | `résumé;x=y.pdf` |
| an encoded-word, then `".pdf` | `résumé".pdf"` | `résumé".pdf"` | `résumé".pdf` |
| an encoded-word, then ` notes.pdf` | `résumé notes.pdf` | `résumé notes.pdf` | `résumé notes.pdf` |

**What moved is `get_phrase`.** 3.13.15 drops the white space between two encoded-words in a
phrase and 3.13.12 keeps it. Measured by swapping that one function: with `get_phrase` taken
from 3.13.12's `email/_header_value_parser.py` and put into 3.13.15's, the service's own
`filename_of` gave the 3.13.12 result for each shape with two encoded-words, while one
encoded-word, and an encoded-word followed by plain text, kept theirs — the controls. Which
patch release between the two made the change was not measured. So every published image up to
0.5.0, all of them built on 3.13.15, joined two encoded-words in a name by a correction in a
grammar that is not the name's, and nothing pinned it; and every one of them rewrote a `;` after
an encoded-word as a parameter, on both interpreters, with `extension` `pdf"` wherever the
rewriting added a quotation mark at the end (the fourth and fifth rows).

**`policy.default` reads the parameter with its own grammar**, and that is a different rule
again — the same on both interpreters:

| The parameter | `compat32` `get_filename()` | `policy.default` `get_filename()` |
| --- | --- | --- |
| continued, white space at the segment boundary between two encoded-words | the encoded-words, undecoded | `naïve-no tes.txt` |
| with a charset, its text an encoded-word | `=?utf-8?Q?x?=.pdf` | `=?utf-8?Q?x?=.pdf` |
| `filename=`, then `filename*=` | `plain.pdf` | `plain.pdf` |
| `filename*=`, then `filename=` | `plain.pdf` | `résumé.pdf` |
| `" .notes. "` | `.notes.` | `.notes.` |

`compat32` takes the plain form whichever comes first, and `policy.default` the one written
first. Both remove white space at the ends of a name and keep its periods. The header as
`policy.default` renders it — which is what `headers{}` shows `[D24]` — keeps the white space at
the ends, and shows one parameter where two were written.

The grammar of unstructured text joined two encoded-words and left everything else as written
for every shape measured, on both interpreters. Hence `[D27]`: the plain form is read with it,
and the rule is written down as its result rather than as any one of these readings.

---

## F22 — the indicator grammar: where the defanged path loses a candidate, and what a run costs

Probed with `probes/grammar.py` on 3.13.12. `defang v0.6.0` and `sweep v0.6.0` measure the
grammar as 0.6.0 shipped it; `layer1` and `layer2` are the comparison the changes to the
grammar in 0.7.0 are held to, and their first run is recorded at the end.

**The defanged path.** A defanged form is found by locating its marker (`[.]`, `[at]`, …),
growing it outwards over the characters `A-Z a-z 0-9 [ ] ( ) { } @ : . _ / -`, at most 2,048
on each side, re-arming the token, and requiring the whole of it to be one candidate of one
grammar. Three properties follow from that construction:

| Written | 0.6.0 returns |
| --- | --- |
| `- one[.]example[.]net`, `. one[.]example[.]net` (the control) | `one.example.net`, `defanged` |
| `-one[.]example[.]net`, `.one[.]example[.]net` | nothing |
| `-hxxp://two[.]example[.]net/path`, `-user[at]three[.]example[.]net`, `-192[.]0[.]2[.]201` | nothing |
| `x (hxxp://two[.]example[.]net/path) y`, `x [one[.]example[.]net] y` | nothing |
| `x one.example.com(two[.]example[.]net) y` | nothing, not even the plain domain in front |
| `x hxxp://two[.]example[.]net/p?q=1&r=2 y` | `http://two.example.net/p` |
| `x hxxp://two[.]example[.]net/~user y` | `http://two.example.net/` |
| `x first.last+tag[at]three[.]example[.]net y` | `tag@three.example.net` |
| `x bücher[.]de y` | `cher.de` |

- **A mark in front of the form is grown into the token**, and the token as a whole is no
  candidate, so nothing is returned: after a hyphen or a period (the known defect), and by the
  same mechanism after a bracket or a parenthesis, which a sentence puts around a form as often
  as a hyphen before it.
- **A character outside the set ends the growth inside a candidate**, and what is left is cut
  (`?q=1&r=2`, `~user`) or distorted into another candidate (`tag@…` for `first.last+tag@…`,
  `cher.de` for `bücher.de`).
- **Every marker is grown**, so a run of markers costs about 147 µs a character: 7.31, 14.55
  and 29.51 s for 50k, 100k and 200k characters of `a[.]`, against 0.02, 0.03 and 0.07 s for
  the same run written plainly (`a.`).

**The grammar on a run.** `sweep` repeats a unit into a run with no white space and doubles the
run from 1,000 characters until one scan takes 0.2 s or the run reaches 128,000, best of two.
The verdict is read from the last doubling, at a size where a per-call cost no longer hides
the term looked for, never from the first ones, where it does, and a ratio above 3 is
measured again, best of five, before it counts. The units are every unit of one and two
symbols and 500 seeded longer ones, 1,690 in all. On 0.6.0, 162 of them grow faster than
linearly at their last doubling, at 2,000 or 4,000 characters, each costing 130–170 µs a
character there: more than half a second for 4,000 characters, with the cost growing as the
square of the length. Before the second measurement was added, two runs counted 176 and 173:
units near the threshold moved between runs, so the count is a size, not an identifier. The
defanged path is among them (`[.]}{.}`); so are the shapes where an address or a URL may start
at every word boundary of a run and read to its end before failing (`a-`, `1+`, `a'`, `#a`).
Real base64 in one line, the `+` and `/` of its alphabet putting a word boundary every few
characters, takes 5.47, 19.05 and 71.92 s for 48k, 96k and 192k characters (`shapes v0.6.0`).

**The comparison every change to the grammar is held to.** `layer1` compares, for each
generated string, the spans `_scan` takes and the candidates made from them, between two
trees; `layer2` compares the full response of every message the test suite sends, the
saved messages and the golden samples, with the tools absent and present. Each prints a
positive control, the same comparison with one input changed. Zero differences is the
criterion, or each difference is recorded as a decision.

The first run, `v0.6.0` against the tree that wrote this entry, which already skips a run past
`MAX_RUN_LENGTH` `[D29]`: `layer1` 0 of 8,318 strings differ, the control 1 of 1; `layer2`
603 messages, 1,206 responses, 10 differ, the control 2 of 2 (one message in both modes).
The ten are five messages in both modes, each one with a run past the limit: the three
messages of the pair test past the limit, which lose the URL and its host and gain
`truncated`; the cost test's, which gains `truncated`; and a 3 MiB body of one run of `x`
from the form-channel test, which gains `truncated` and nothing else.

**After the scan loop (0.7.0).** A URI with a scheme and an address are found by their
anchors, `:` and `@`: each anchor is read once, for where its stretch begins, which starts in
it the grammar admits, and where the match after it ends, and the earliest match at or after a
position is the first admitted start of the first anchor that has one. `sweep .` then counts
21 units, and every one of them holds a marker of the defanged path: the shapes where an
address or a URL could start anywhere are gone. Real base64 in one line takes 0.01, 0.03 and
0.06 s. The control is ordinary text at 192k characters: prose takes 0.09 s against 0.14 s on
0.6.0, and prose with a link and an address in every sentence 0.23 s against 0.19 s, the cost
of reading each anchor where they are dense. `layer1`, now 38,318 strings with short ones
dense in anchors, marks and white space, gives 0 differences against the tree before the
change and against `v0.6.0`; the same comparison with a period admitted as the start of a
local part shows 41, and with no scheme starting after a period 132. `layer2` gives 0 of
1,208 responses, leaving out what the cost tests send, which the old tree takes minutes over.

**The readers a run made quadratic outside the scan's search.** `shapes` and `paths`, on
`v0.6.0` and after the change, the largest size of each:

| Reader | Input | 0.6.0 | 0.7.0 |
| --- | --- | --- | --- |
| trimming a URL's tail | 192k of `}` after the URL | 52.55 s | 0.05 s |
| trimming a URL's tail | 192k of `.`, `;`, `:`, `!` or `?` | 1.07–1.10 s | 0.03 s |
| the address in CSS `url(` | 16k characters of `url(` | 1.32 s | 0.01 s |
| a `Received` field | 128k characters of `from a (` | 2.46 s | 0.01 s |
| `Authentication-Results` parameters | a run of 32k `a` after `spf=pass` | 16.88 s | 0.00 s |
| listing a value's places | one value in 20,000 places | 42.49 s | 0.46 s |

Each grew by about four for twice the input on 0.6.0. A tail of `,`, `)`, `]`, `"` or `'` was
cheap already, because each of those ends a URL: the tail was never part of it. Trimming took
a character off at a time and copied the rest, counting brackets again for a closer; it now
finds the cut in one pass and slices once. The other three readers had a branch that read to
the end of a run and failed there, from every start in the run; each now reads a run once. A
value's places were a list searched before each was added; a set beside the list answers
now. `test_exact_rewrites` compares each rewritten reader with the pattern or loop it
replaced, kept in the test as its definition. `layer1` gives 0 of 38,318 against the tree
before, `layer2` 0 of 1,212. The control, ordinary text at 192k characters, read 0.07 s for
prose against 0.11 s on 0.6.0 and 0.18 s for prose dense with links against 0.13 s; the same
inputs read 0.09 against 0.14 and 0.23 against 0.19 in the run of the previous change, so the
direction holds and the size moves by a third between runs.

---

## F23 — `html.parser` fed in pieces: where an empty comment ends depends on what has arrived

Probed with `f23_html_parser_fed_in_pieces` in `probes/email_stdlib.py` on 3.13.12 and on
3.13.16 inside the published 0.6.0 image.

The deadline has to stop the HTML scan somewhere `[D10]`. The obvious way is to feed the parser
in pieces and ask the deadline between them, each piece cut just before a `<`, where a text
node ends anyway. That reads the document as one feed does only if the parser decides nothing
on the strength of what it has not been given yet.

| The document, cut before `<b>` | 3.13.12, at once | 3.13.12, in two pieces | 3.13.16, either way |
| --- | --- | --- | --- |
| `<!--><b>x</b>-->` | one comment, `><b>x</b>` | an empty comment, `b`, `x`, `-->` as text | an empty comment, `b`, `x`, `-->` as text |
| `<!---><b>x</b>-->` | one comment, `-><b>x</b>` | as above | as above |
| `<!-- c --><b>x</b>` (the control) | a comment, `b`, `x` | the same | the same |

**What moved is `parse_comment`.** 3.13.12 looks for a `-->` anywhere in what it holds, and
takes the abrupt close of an empty comment (`<!-->`, `<!--->`) only when there is none, so
the result depends on whether the rest of the document has arrived. 3.13.16 takes the abrupt
close first, as HTML5 does, and gives one result either way. Which patch release made the
change was not measured.

On 2 000 generated documents, each fed in pieces of at least 1, 3 and 8 characters cut before a
`<` and compared with one feed: 1 283 of 6 000 differ on 3.13.12 and none on 3.13.16. Without
the two comment openers in the generator, none differ on 3.13.12 either. The control cuts every
three characters, wherever that falls, and differs on 1 513 of 2 000 documents on 3.13.12 and
1 236 on 3.13.16, so the comparison sees a difference when there is one.

Two consequences:

- **The parse of `<!-->` moved.** Text after it, up to a later `-->`, is a comment on 3.13.12
  and text on 3.13.16. So `text_from_html`, and the candidates read from the HTML text,
  follow the image's interpreter for such a document. That is F10's "behaviour that depends
  only on CPython's version", made concrete.
- **Pieces read like one feed only by the interpreter's grace.** Hence the HTML scan is fed
  once, and the deadline is asked from inside, before each start tag, end tag, run of text and
  comment the parser hands over. When it has passed, the scan stops there. That reads the same
  on every interpreter, because nothing about the parse changes.

The text scan needs no such care. A chunk cut just before white space gives exactly what the
whole text gives, because no candidate contains white space and every lookaround of the
grammar reads white space and the end of a chunk alike.
`test_observables::test_a_text_scanned_in_chunks_gives_what_one_scan_gives` compares the two on
generated texts. The same comparison on 4 000 texts, run with the branch's source inside the
0.6.0 image, gave no difference on 3.13.16 either.
