# mail-dissect — functional specification

**Status: APPROVED (2026-09-17).** This file is the source of truth for implementation.
Design decisions are marked `[D#]` inline and recorded in [§22](#22-decision-record);
measured standard-library behaviour they build on is documented in
[`research/NOTES.md`](research/NOTES.md) as `F#`.

## 1. Purpose

mail-dissect is a self-hosted HTTP service that takes one raw RFC 5322 message and returns a
**deterministic structural dissection** of it as JSON, plus the large parts as downloadable
artifacts. It exists so that every consumer — a SOAR pipeline, an analyst's script, another
service — stops re-implementing MIME descent, header decomposition, link extraction and
indicator scraping, each slightly differently and each slightly wrong.

The service answers one question: **what does this message contain and say?**

## 2. Hard boundaries (by design, permanently)

- **It does not judge.** No verdict, no score, no thresholds, no weights, no lists of "free
  mail providers", "risky extensions" or "suspicious keywords". Judgement depends on who is
  asking: the same domain is internal to one consumer and foreign to the next; the same
  attachment type is routine in one process and an alarm in another. A service that decides
  this on the consumer's behalf is useful to exactly one consumer and an obstacle to the rest.
- **Reference data is not policy.** Recognising a type needs knowledge of the world — whether
  `md` is a top-level domain, whether `docx` is a file extension — so the service uses
  **registries** (§12), the same way it uses character-encoding tables. The boundary runs
  where dependence on the asker begins: a public-suffix list describes the world and is the
  same for everyone; a list of "free mail providers" describes somebody's point of view. The
  first is allowed, the second is not.
- **It makes no outbound connections** other than to the two optional tools configured by the
  operator (§14). No reputation lookups, no DNS, no fetching of remote resources referenced by
  the message. The service is designed to run in a network with no route out and must be fully
  functional there — a functional requirement, verified by a test, not a claim.
- **It never executes.** No scripts are interpreted, no archives are expanded, no declared
  content type is trusted. Rendering is performed by a separate component (§14.2) because
  rendering HTML is running someone else's code and has a different risk profile from parsing.
- **It decomposes everything it decomposes anyway, and selects nothing.** Where taking
  something apart costs nothing because the parser already reads it, the whole of it is
  returned. Selecting a subset is a decision about what matters — judgement in disguise, and a
  guarantee that the next consumer will have to work around the contract.

**The rule that settles design doubts:** is this a fact, or a representation of content, that
can be derived from the message alone — without knowing who reads it and why? Facts (headers,
their decomposition, MIME structure, hashes) and representations (text, HTML, text extracted
from a document, a screenshot) belong to the service. Judgements, lists and thresholds do not.

## 3. API conventions

- All paths carry a **`/v1` prefix**; it is part of the contract (§21).
- `Content-Type: application/json`, UTF-8, for every response except artifact bytes.
- No trailing-slash redirects: `redirect_slashes` is off and a trailing-slash path is an
  enveloped 404.
- The service is **unauthenticated by design** — it is meant for an internal network of known
  composition. A deployment on a network whose operator does not control its membership should
  put an authenticating layer in front of it; an extra header does not break this contract and
  can be added without a version change.

## 4. Endpoints

| Endpoint | Role |
| --- | --- |
| `POST /v1/dissect` | the message on input, in either of two equal forms: `multipart/form-data` with field `eml`, or raw bytes in the body with `Content-Type: message/rfc822`. Returns §5 |
| `GET /v1/artifact/{dissect_id}/{artifact_id}` | raw artifact bytes; response headers never repeat anything the message said (§13.3) |
| `GET /v1/health` | service and optional-dependency state (§14.3) |

Both input channels must produce identical results for identical bytes, so the multipart body
is read by the service itself rather than through the framework's file handling, which caps
and text-decodes non-file fields (F11).

**Artifact access rests entirely on identifiers being unguessable** (the capability-URL
pattern, as with presigned URLs). Three requirements follow, and without any of them the whole
protection collapses:

1. `dissect_id` and `artifact_id` come from a cryptographic random generator with **at least
   128 bits of entropy**. A counter, a timestamp or a digest of the content is not acceptable.
2. **There is no listing endpoint.** `GET /v1/artifact/{dissect_id}` without the second
   identifier returns 404, never a list — otherwise one identifier is enough to derive the rest.
3. **`artifact_id` never reaches the application log.** A logged artifact identifier is a
   logged access key. `dissect_id` may be logged and is returned in the error envelope: on its
   own it opens nothing, because a download needs both, and without it the service is
   undiagnosable in production.

Artifacts are a separate request rather than base64 inside the JSON because consumers usually
pass the response through layers that handle very long strings badly. Bytes stay bytes.

## 5. Response shape of `POST /v1/dissect`

```
{ ok:bool, dissect_id:str, source{size:int, md5:str, sha1:str, sha256:str},
  messages:[{ index:int, depth:int,                       # depth 0 = top-level, 1+ = nested
              headers:{ "<name>": ["<value>", …], … },    # ALL headers, names lowercased, values as a list
              addresses{ "<header name>": [ {display_name:str|null, address:str|null,
                                             local_part:str|null, domain:str|null} ], … },
              auth:[{method:str, result:str, params:{…}}],
              received:[{from_host:str|null, from_ip:str|null, by_host:str|null, with:str|null,
                         id:str|null, for:str|null, timestamp:str|null}],
              body{ text:str|null, html:str|null, text_from_html:str|null,
                    text_artifact_id:str|null, html_artifact_id:str|null,
                    text_from_html_artifact_id:str|null,
                    text_part_index:int|null, html_part_index:int|null },
              mime_parts:[{content_type, disposition:str|null, filename?:str|null,
                           content_id:str|null, size:int, charset_declared?:str|null,
                           charset_used?:str|null, transfer_encoding?}],
              links:[{text:str|null, href:str, scheme:str|null, host:str|null, port:int|null,
                      userinfo:str|null, path:str|null, query:str|null, fragment:str|null,
                      host_idn:str|null, host_punycode:str|null,
                      rewritten_from:str|null, unwrap_failed:bool, cid_part:int|null}],
              resources:[{element:"img"|"iframe"|"link"|"style"|"other", href:str,
                          scheme:str|null, host:str|null, port:int|null, userinfo:str|null,
                          path:str|null, query:str|null, fragment:str|null,
                          host_idn:str|null, host_punycode:str|null,
                          rewritten_from:str|null, unwrap_failed:bool, cid_part:int|null}],
              observables:[{value:str, value_raw:str, type:str, subtype:str|null,
                            defanged:bool, ambiguous:bool, occurrences:int,
                            sources:[{kind:"body_text"|"body_html"|"header"|"attachment",
                                      header_name:str|null, header_index:int|null,
                                      part_index:int|null}, …]}],
              attachments:[{part_index:int, artifact_id:str|null, text_artifact_id:str|null,
                            filename:str|null, extension:str|null,
                            disposition:str|null, content_id:str|null,
                            declared_mime:str, detected_mime:str|null,
                            size:int, md5:str|null, sha1:str|null, sha256:str|null}] }],
  artifacts:[{artifact_id:str, message_index:int, part_index:int|null,
              kind:"eml"|"headers"|"body_text"|"body_html"|"body_text_from_html"
                   |"attachment"|"attachment_text"|"screenshot",
              filename:str, mime:str, size:int, sha256:str}],
  tools:{ tika:"ok"|"down"|"timeout"|"skipped"|"disabled",
          renderer:"ok"|"down"|"timeout"|"skipped"|"disabled" },
  flags:[ "truncated" | "malformed_mime" | "encoding_fallback"
          | "attachment_unreadable" | "artifact_store_failed" ] }
```

### 5.1 Closed value sets

**The value sets of `type`, `subtype`, `sources[].kind`, `artifacts[].kind`, `flags` and
`tools` are CLOSED.** Extending any of them is a version change (§21), not an addition.

**`encoding_fallback` fires when, and only when, the service could not take the material's
word for how it is encoded, or had to substitute something in order to read it.** Not taking
its word: a declared charset — a part's (§7.2), an encoded-word's, an RFC 2231 parameter's —
that cannot be looked up, or that does not decode what it declares. Substituting: U+FFFD
standing where the material had bytes that do not decode, a header byte that is not UTF-8
among them `[D20]`. Material that reads without loss does not raise it, whichever path it
took — raw UTF-8 in a header, say — because a flag that also fires where nothing happened
teaches its consumer to ignore it exactly when it starts to matter.

The reason is practical, not aesthetic: a field with an open value set — or a bag with a
neutral name such as `facts`, `extras` or `meta` — accumulates consumer policy over time,
first as a small convenience and then as a dependency that cannot be withdrawn. When something
is missing, the right answer is a new, named field, never a bag. `[D14 context]`

The same applies to **header selection**: `headers` returns all of them without choosing, and
`addresses` and `auth` decompose in full everything that can be decomposed deterministically.
Promoting a few "more important" ones to first-class fields would be a decision about what
matters, and that belongs to the consumer.

### 5.2 Everything is addressed by index, and there is one index

The position in `mime_parts[]` is the only identifier of a part in the whole contract:
`attachments[].part_index`, `body.text_part_index`, `body.html_part_index`, `links[].cid_part`,
`resources[].cid_part`, `artifacts[].part_index` and `sources[].part_index` all use it. A
filename is not an identifier — two attachments may share one or have none.

The same holds for headers: `header_name` says which, `header_index` says which one of them,
because `Received`, `Authentication-Results` and `DKIM-Signature` occur repeatedly and the
difference between the first and the third entry matters.

`attachments[]` repeats a few fields of its part (`filename`, `size`, `declared_mime`,
`disposition`, `content_id`) for convenient filtering; the full description of a part always
lives in `mime_parts[part_index]`.

## 6. MIME structure: parts, roles, nesting

### 6.1 The tree

`mime_parts[]` is the canonical list of all parts of one message in tree-walk order, and it is
what assigns the indices used across the contract.

The tree is built by the standard library's `email` package with `policy.compat32` `[D11]`.
Two narrow pieces are added on top:

- a **byte-range locator**, used only for `message/rfc822` parts, which finds the part's body
  span in the input. It is self-checking: a located span is accepted only if re-parsing it
  yields the same structure the standard library returned for that part; a mismatch raises
  `malformed_mime` rather than silently disagreeing `[D12]`.
- a **cheap pre-pass** over the raw bytes that establishes the number of parts and the nesting
  depth **before** the tree is built `[D13]`.

### 6.2 Nesting

A message may carry another message as a `message/rfc822` part, at several levels and several
at once. Each becomes its own entry in `messages[]` with a `depth` field: `0` for the top-level
message, `1` and above for nested ones, in order of appearance. **The top-level message is
always present**, also when there is no nesting, and is dissected exactly like the others.

A nested message also appears in its parent's `attachments[]` — it is a MIME part, after all —
and its `eml` artifact returns it in the original (§13.2).

**A nested message stays a message regardless of transfer encoding.** A `message/rfc822` part
with `Content-Transfer-Encoding: base64` must be decoded and parsed recursively. The trap is
named here because it is silent: the standard library parses such a part into a bogus
`text/plain` child (F2), so an implementation that trusts the tree builds a wrong `messages[]`
and reports no problem at all.

**A nested message counts once.** It is both a MIME part of its parent and a separate entry in
`messages[]`, so its bytes count towards the limits once, without doubling through content.

### 6.3 Body versus attachment — one rule

The split follows from a single walk, with no `Content-Disposition` criterion:

- **The body** is the first `text/plain` part and the first `text/html` part found in the
  message's main flow: descending through `multipart/mixed` to the first content part, through
  `multipart/related` to the root part, and choosing the matching type inside
  `multipart/alternative`. The walk does not descend into `message/rfc822` — a nested message
  has its own body. Where `mixed` holds two `text/plain` parts, **the first is the body and the
  second is an attachment**.
- **The choice is explicit and reversible:** `body.text_part_index` and `body.html_part_index`
  say which parts were taken as the body. A consumer who would choose differently has the
  complete data in `mime_parts[]` and does not need to ask for a contract change.
- **An attachment is any part that is not a container (`multipart/*`) and was not chosen as the
  body.** Instead of deciding for the consumer, each entry carries `disposition` (`attachment`,
  `inline` or absent) and `content_id`, and filtering is theirs. An image embedded through
  `cid:` is therefore an attachment marked `inline` — whoever does not need it rejects it with
  one condition, and whoever is studying what the message loads on open has it immediately.
- The same rule yields, with no special case, that **a nested message is an attachment** of its
  parent: it is a part, it is not a container, and it is not the body.

## 7. Headers

- `headers` carries **every** header, names lowercased, values as a list in order of
  appearance, in the form they were written (after RFC 2047 decoding).
- `addresses` decomposes **every address header present** — `from`, `to`, `cc`, `bcc`,
  `reply-to`, `sender`, `return-path`, `resent-*` — into `display_name`, `address`,
  `local_part` and `domain`. Decomposing an address costs the same for three headers as for
  all of them, and choosing three would be a decision about which ones matter. Two of the
  headers in that set are not covered by the standard library's header registry and must be
  remapped before use (F6).
- `received` decomposes each `Received` header into a hop
  `{from_host, from_ip, by_host, with, id, for, timestamp}`, in header order (newest first, as
  in the message). Fields absent from an entry are `null` — the header is often incomplete and
  that is normal.
- `auth` decomposes `Authentication-Results` into a list of results: **every method present**
  (`spf`, `dkim`, `dmarc`, `arc` and any other), with the value as written (`pass`, `fail`,
  `softfail`, `permerror`, `none`, …) and its accompanying parameters.

Decomposition never replaces the raw header: everything above also remains in `headers`.

RFC 2047 decoding goes through the standard library's `HeaderRegistry`, never through
`make_header(decode_header(...))`, which raises on input a hostile sender fully controls (F7).

### 7.1 Declared versus detected

An attachment carries `declared_mime` (what the message says) next to `detected_mime` (what the
content signature says); a part carries `charset_declared` next to `charset_used` (the encoding
actually used for decoding). **The service does not comment on a discrepancy** — it returns
both values.

### 7.2 Character encodings

Everything the service reads — body, links, candidates — is read from the **decoded** content
of a MIME part, never from raw bytes. `quoted-printable` breaks long URLs with a `=CRLF`
sequence in the middle, so a regular expression run over a raw message returns truncated
garbage; this concerns every URL, not just special cases.

The decoding ladder is fixed, so that two implementations agree:

1. **BOM sniff** (UTF-8, UTF-16LE/BE, UTF-32LE/BE) — a BOM wins outright.
2. **The declared charset**, if `codecs.lookup()` resolves it, decoded with `errors="strict"`.
3. **HTML meta sniff** (`text/html` only): `<meta charset>` / `<meta http-equiv>` within the
   first 4096 bytes, read as latin-1; strict decode.
4. `utf-8`, strict.
5. `cp1252`, strict.
6. `latin-1`, which cannot fail and terminates the ladder.

`charset_declared` is the parameter exactly as written; `charset_used` is the canonical name of
the codec actually used. **`encoding_fallback`** is raised when a declaration existed and the
codec actually used differs from it, or when any replacement character was substituted — the
two halves of its definition in §5.1. No
statistical charset detection is used: its verdicts change between library versions, which
would make the determinism criterion (§17) depend on a third registry version.

## 8. Bodies and their representations

A message has up to three representations of its body, and each is treated identically:
`body.text` (the original `text/plain` part), `body.html` (the original `text/html` part) and
`body.text_from_html` (a deterministic text rendering of the HTML, §9.3).

**Inline content has a threshold, the link is always there.** Each of the three carries its
content directly while it fits in `MAX_INLINE_BODY_BYTES`; above the threshold the field is
`null` and the content exists only as an artifact. **Each of the three has its own threshold
and its own link** `[D4]` — text derived from HTML can be as large as the HTML itself, and a
consumer cannot reproduce it from the `body_html` artifact, because the conversion is a rule of
this service, not their job.

`text_artifact_id`, `html_artifact_id` and `text_from_html_artifact_id` are filled **regardless
of the threshold**, so a consumer never has to guess whether `null` means "there was no
content" or "the content is elsewhere": when there was no content, the link is `null` too.

**The exception has its own flag:** when an artifact write fails (`artifact_store_failed`), the
service returns the content inline **regardless of the threshold** if it possibly can — a large
response beats losing the content — and when even that is impossible, the pair of empty fields
is unambiguous thanks to the flag.

## 9. Links, resources and HTML text

HTML is parsed with the standard library's `html.parser` `[D15]`, in a single pass that emits
an ordered event stream; `links[]`, `resources[]`, `text_from_html` and the HTML part of the
observables scan are all consumers of that one stream. That is what makes document order
(§11.1) implementable and what keeps an anchor's href from being counted twice.

### 9.1 Two disjoint categories

`links[]` are **anchors** (`<a>`, `<area>`) — something the recipient has to click.
`resources[]` are addresses **loaded automatically** when the message is opened. The separation
is a structural fact, not a judgement: they are two different events in the recipient's client
and the consumer is entitled to tell them apart.

| `element` | Read from |
| --- | --- |
| `img` | `img[src]`, each URL in `img[srcset]`, `input[type=image][src]`, `source[src]`, each URL in `source[srcset]`, `video[poster]` |
| `iframe` | `iframe[src]`, `frame[src]` |
| `link` | `link[href]`, any `rel` |
| `style` | every `url(...)` in a `<style>` element or a `style` attribute, and `@import` |
| `other` | `object[data]`, `embed[src]`, `video[src]`, `audio[src]`, `track[src]`, `body[background]`, `table|td|th[background]` |

**No filtering by scheme.** `mailto:`, `tel:`, `cid:`, `data:` and relative addresses enter on
equal terms with `http(s)`; `scheme` is a separate field and `host` is `null` where the scheme
has none. A `cid:` address pointing at a part of the same message carries that part's index in
`cid_part` (matching is exact, angle brackets stripped, within one message only). **Relative
addresses enter as they are**, with `scheme: null` and `host: null` — in a mail message they
are useless, because there is nothing to resolve them against, but their presence is a fact
about the content and the service does not hide it.

Every address is **decomposed** into `scheme`, `userinfo`, `host`, `port`, `path`, `query`,
`fragment` and the IDN/punycode forms of the host. `userinfo` in particular carries the `@`
substitution trick, and a consumer should not have to dig it out themselves.

### 9.2 Addresses come only from places where they are addresses

From text content, from the `href` of anchors, and from the source attributes listed above —
**not from arbitrary attributes**. The scanner reads a **fixed allowlist of attributes** and
CSS `url()` tokens; it never iterates over all attributes. Namespace declarations (`xmlns` and
the like) are therefore not a source of candidates, not because they are filtered out by value
but because they are never read. **This is a structural rule, not an exclusion list:** the
service knows no domain patterns and filters nothing by value.

### 9.3 `text_from_html`

A deterministic text rendering of the HTML body: no markup, whitespace collapsed. It does not
replace `body.text`, which is the original `text/plain` part; when there is none, `body.text`
is `null` and the text form is still available and identical for every recipient.

The rules, precise enough for two implementations to agree:

1. Comments, doctype, processing instructions and CDATA are dropped.
2. The content of `script`, `style` and `template` is dropped. The content of `noscript` and
   `title` is kept.
3. Attributes are never text — `alt`, `title` and `aria-*` contribute nothing. This is the same
   structural rule as §9.2.
4. `br` emits `\n`. The start and the end of every element in the block set emit `\n`; `td` and
   `th` boundaries emit one space. Block set: `address article aside blockquote center dd
   details dialog div dl dt fieldset figcaption figure footer form h1 h2 h3 h4 h5 h6 header hr
   li main nav ol p pre section summary table tbody tfoot thead tr ul`.
5. U+00A0 and every other Unicode space separator become U+0020; `\r\n` and `\r` become `\n`.
6. Collapsing, in this order: each run of `[ \t\f\v]` becomes one space; spaces adjacent to
   `\n` are removed; runs of three or more `\n` become exactly two; the result is stripped.
   **`pre` is not exempt** — uniformity is worth more here than fidelity, and the raw HTML
   artifact preserves the original.

## 10. Link unwrappers

Mail filters replace addresses in the content with their own. The unwrapper table is
**declarative** and configured as JSON in `UNWRAPPERS`; an entry has:

| Field | Required | Meaning |
| --- | --- | --- |
| `host_suffix` | yes | host match **by suffix**, on a label boundary (not a regular expression) |
| `source` | yes | where the target is: `query:<parameter name>` or `path_segment:<number>` (**zero-based**) |
| `decoder` | yes | `percent`, `base64`, `base64url` or `none` |
| `strip_prefix` | no | string to cut from the start of the extracted value |
| `strip_suffix` | no | string to cut from the end |

**Regular expressions from configuration are excluded** — a declarative entry can be validated
at startup and carried between deployments; a hand-written pattern can be neither.

- A syntax error in `UNWRAPPERS` **stops the service from starting**; silently ignoring bad
  configuration would be worse than not starting.
- With several matching entries, **the first in configuration order** wins.
- Unwrapping repeats **iteratively to a fixed point**, with a hard limit of a few passes,
  because mail is sometimes passed through two gateways; `rewritten_from` then carries the
  **outermost** address, the one that actually stood in the message.
- When an entry matches but unwrapping fails (missing parameter, broken encoding), the link is
  left unchanged and gets **`unwrap_failed: true`** — otherwise "there was nothing to unwrap"
  would be indistinguishable from "we tried and failed", that is, from a bad configuration.
- Unwrapping applies to **both `links[]` and `resources[]`**, and both carry `unwrap_failed`
  `[D2]`.

**Reversibility is a result of trying, not a declaration.** The service does not know, and has
no way to know, which wrappers are irreversible; it only knows whether it can unwrap an entry
from the table. A wrapper that replaces the address with an irreversible identifier simply has
no entry, so its links pass through unchanged. **We never expand through the network.** After
unwrapping, `href` carries the target, `host` is the target's host, and the decomposition in
§9.1 concerns the target.

**The table is empty by default.** A service without configuration unwraps nothing; shipping a
ready-made list of matches would be a choice about whose filters matter. The README gives
entries for the most common wrappers as **configuration examples to copy**, not as a default.

## 11. Observables

`observables[]` is the **canonical list of all indicators** found in one message, no matter
where they lay: in text content, in HTML (including as an anchor or resource address), in
headers, and in text extracted from documents. Whoever wants a complete list of addresses takes
`observables` and can be sure nothing escaped. `links[]` and `resources[]` are a **supplement,
not an alternative**: they add HTML context (anchor text, element kind) that a flat list of
indicators does not carry. The same address appears in both places, and that is intended.

**Found hashes and computed hashes are two different things.** `observables` carries hashes
**written in the content** (someone pasted a checksum into the message). A hash **computed from
an attachment's bytes** is in `attachments[].sha256` (and `md5`/`sha1`) and is not a candidate
found in the content — mixing them would blur the difference between what the message says and
what the message contains.

**Taxonomy — closed and our own:** `type` ∈ `url` · `domain` · `ip` · `email` · `hash` ·
`filename`; `subtype` (optional) ∈ `ipv4` · `ipv6` · `md5` · `sha1` · `sha256` · `sha512`. The
service defines this set itself, independently of whichever library it types with internally
`[D7]`; another tool's identifiers do not become part of this contract by being used.

### 11.1 Scan order

Within one message, in this order `[D9]`: **headers** in header order → the `text/plain` body →
the **HTML body in document order** → texts extracted from documents, by ascending
`part_index`. The collector is append-only, so candidates derived from an optional tool can
only extend the tail: the deterministic core of the list does not shift when the tool is absent
or fails (test 62). `observables[]` is per message, so ordering between messages is not a
question.

### 11.2 Recognition is grammar crossed with a registry

Grammar says "this string has the shape of a domain", the registry says "this final label
exists in the world". Neither suffices alone: grammar alone would call `wersja.1.2` a domain,
and a registry alone could not tell an address from a sentence.

- **`url`** — a string with a scheme per RFC 3986; **also without a scheme** when it has a path
  or a `www.` prefix (`bit.ly/xyz`, `www.example.com`), because shorteners and protocol-less
  addresses are everyday content and a consumer should not lose them.
- **`domain`** — labels per RFC 1035 ending in a **public suffix from the registry**; also
  derived from a URL's host **and from an email address's domain** (decompose, do not select —
  asymmetry between those two sources would be accidental).
- **`ip`** — IPv4 and IPv6 grammar, with no filtering of private or reserved addresses.
- **`email`** — `addr-spec` per RFC 5322.
- **`hash`** — a hexadecimal string of length 32, 40, 64 or 128.
- **`filename`** — a filename pattern with a **known extension from the registry**. Attachment
  filenames are **not** candidates from content: they are a fact in `attachments[]` and do not
  travel to `observables`.

Matching is one compiled alternation applied in a single pass per unit, and **the order of the
alternatives is part of the contract**, because it is what resolves overlaps: leftmost match
wins, and at the same position the earlier alternative wins.

```
1 defanged form     2 url with scheme   3 email   4 schemeless url
5 ipv6              6 ipv4              7 hash    8 registry-gated token (domain / filename)
```

**The defanged form is matched first, and that ordering is load-bearing.** `hxxp:` is a
syntactically valid scheme, so a URL alternative placed ahead of it swallows
`hxxp://zly[.]host` and returns a broken address instead of a re-armed one. A URI with a
scheme comes second, and an opaque one is required to carry an `@` or a `/` — the structural
test that separates `mailto:a@example.com` from the `Note:this` of an ordinary sentence,
without a list of schemes we happen to approve of.

IPs are matched loosely and validated with a real IP parser. Trailing punctuation is trimmed
from URLs by a fixed rule: strip trailing `.,;:!?"'`, then strip unbalanced `)]}>`.

### 11.3 Canonical form, defanging, ambiguity, deduplication

- **Canonical next to original.** `value` is normalised: host lowercased, no trailing dot, in
  punycode; the URL's path and parameters are **untouched** (they are case-sensitive).
  `value_raw` is exactly what stood in the material. The service does not choose which form is
  "the right one" — it returns both. Punycode conversion is best-effort: where it fails, the
  canonical host is the lowercased original and `host_punycode` is `null`; it never raises.
- **Re-arm the notation, but mark it.** Forms such as `hxxp://`, `[.]`, `(dot)`, `[:]` are a
  convention meant to make an address unclickable. `value` is re-armed, `value_raw` keeps the
  original, and `defanged: true` says the difference comes **from re-arming, not from
  normalisation**. Closed table: `hxxp`→`http`, `hxxps`→`https`, `fxp`→`ftp`,
  `[.]`/`(.)`/`{.}`/`[dot]`/`(dot)`→`.`, `[:]`→`:`, `[at]`/`(at)`/`[@]`→`@`. Defanging never
  sets `ambiguous`.
- **A `domain`/`filename` collision yields two entries with `ambiguous: true`.** `raport.zip`
  and `README.md` satisfy both grammars, because `zip` and `md` are simultaneously public
  suffixes and file extensions. The service does not guess: it emits both candidates and flags
  them, so a consumer can drop them with one condition if they are not interested. Where the
  resolution is unambiguous — `faktura.pdf`, because `pdf` is not a public suffix, or
  `example.org`, because `org` is not an extension — there is one entry without the flag.

  **`example.com` is ambiguous, and so is `example.org`.** Measured against the shipped
  snapshots, **60 of the 1441 single-label public suffixes are also file extensions** — 4.2%
  of them, but the 4.2% includes `com` (the extension of `application/x-msdownload`) and
  `org` (`text/x-org`). Every `.com` and `.org` domain in a message therefore yields a
  `filename` candidate beside it, both flagged. `net`, `info`, `io`, `dev` and `app` do not
  collide. This is the rule working rather than failing — two registries genuinely claim the
  string, and the flag is what lets a consumer drop one side with a single condition — but it
  is a larger share of ordinary mail than the `raport.zip` example suggests: `com` and `org`
  are the two commonest domains there are, so **the collision is the ordinary case, not a
  corner one** (F14). A consumer reading `observables[]` without filtering on `ambiguous`
  will see a list close to twice the length they expected, and should not read that as a
  defect. **The flag concerns this collision
  only** and does not mean "careful, this might be a coincidence": a version number that looks
  like an IP address, or an identifier that looks like a hash, are recognised without
  reservation, because grammatically that is what they are.
- **Sentence noise is accepted deliberately.** `…kliknij tutaj.To jest ważne` with no space
  after the full stop yields a `domain` candidate, because `to` is a public suffix. There is no
  clean rule for this — filtering such cases by typography would be a heuristic, and clever
  rules break quietly. The consumer gets **a candidate, not a verdict**, and has the means to
  reject it.
- **Do not filter IP addresses.** Private, loopback, reserved — all enter. Whether an address
  from an internal network is interesting depends entirely on who is asking.
- **Deduplicate by the pair (`value`, `type`).** The same address five times is one entry with
  `occurrences: 5` and a `sources[]` list of the places it occurred. `sources[]` is the ordered
  list of **distinct places**, deduplicated by `kind` + `header_name` + `header_index` +
  `part_index` `[D14]`: five hits in one body is `occurrences: 5` with one source. Repetitions
  carry no information; the count and the places do.
- **Order is order of occurrence** (for deduplicated entries, of the first occurrence). No
  sorting: sorting would destroy the information the order carries and adds nothing to
  determinism.
- **Fan-out does not double-count.** A URL yields its host as `domain` (or `ip` when numeric);
  an email address yields its domain. A derived candidate carries the same source and is
  emitted immediately after its parent. The parent match consumed the span, so the bare-domain
  alternative never sees the host inside a URL.

## 12. Registries

The service uses two registries: the **public suffix list** (domain recognition, including
multi-label suffixes such as `example.co.uk`) and a **list of known file extensions**
(resolving collisions with filenames). Three requirements follow `[D8]`:

1. The registries are **built into the image** as a snapshot. The service has no route out and
   **must not fetch them at runtime** — a data update is not a reason to break the no-egress
   rule. Updating a registry is a new image release.
2. Registry versions are **exposed in `/v1/health`**, because the result of recognition depends
   on them: a new suffix in the registry changes the classification of the same string. Where a
   registry has no release number of its own, its version is **the snapshot date together with
   a digest of its content**, because that same identification enters the determinism criterion
   (§17) and must not depend on who built the image.
3. The registries keep their own licences, also when the project is under a different one.

The extension registry knows only extensions with a **registered media type**, which leaves
out the script formats (`scr`, `pif`, `hta`, `ps1`, `vbs`, `wsf`, …) — see F13. A filename
written in body text with one of those yields no `filename` candidate. Attachment filenames
are unaffected, being a fact in `attachments[]` rather than a candidate (§11.2).

A second registry would not close the gap: Apache Tika's globs add five of the fifteen
formats measured and still miss `scr`, `hta` and `ps1`, because both registries are keyed by
media type and these formats have none. Curating a list ourselves is worse: the selection
criterion would slip from "documented format" to "risky format" at the first opportunity, and
the service would start carrying somebody's point of view — precisely what §2 forbids.

**So the mechanism is ours and the content is the deployment's** `[D22]`, the same shape as
the unwrapper table (§10). `EXTRA_FILE_EXTENSIONS` adds extensions for one deployment;
it is **empty by default** and **additive only** — it never removes anything from the
registry. A supplied extension behaves like any other: one that is also a public suffix
produces the `domain`/`filename` collision of §11.3 with `ambiguous: true`, with no special
case. A value that is not extension-shaped stops the service at startup, because an entry
that silently never matches reads as "this deployment added nothing".

The configured value is **reported in `/v1/health`** — both as a list and folded into the
registry version string as `+extra<count>/<digest>` — and it is an input to determinism
(§17) on the same terms as the registry versions themselves: two deployments must not be able
to report the same version while disagreeing about `payload.scr`. README carries examples to
copy, never a default.

Matching against the public suffix list (exact rules, `*` wildcards, `!` exceptions) is
implemented in this project rather than taken from a package: the available packages carry
their own snapshot, which would fork the version string that `/v1/health` promises.

**Only the ICANN section of the list is loaded** `[D21]`. The file also carries a PRIVATE
DOMAINS section — suffixes that companies register for delegation of their own (`github.io`,
`blogspot.com`, `s3.amazonaws.com`). Loading it would change recognition, because a `domain`
needs at least one label in front of a public suffix: with the PRIVATE section in, a bare
`blogspot.com` or `github.io` written in a message yields **no candidate at all**, which is a
silent loss of exactly the kind of address messages carry. The PRIVATE section is also the
half that is closest to being somebody's point of view — an opt-in list that changes for
commercial reasons — while the ICANN section describes actual delegation, which is the
distinction §2 draws between reference data and policy.

Which section is loaded is an **input to recognition and therefore to determinism** (§17), and
a version number alone does not reveal it, so the version string exposed in `/v1/health` names
it: `<snapshot date>+<section>/<first 12 hex characters of the content digest>`, for example
`2026-09-17+icann/9f2b1c4d7e08`. The same snapshot date, section and digest are recorded in
`data/registries.json` next to each registry's licence.

## 13. Artifacts

### 13.1 What exists

The original message, the headers, the text body, the HTML body, the text derived from HTML,
every attachment, the text extracted from an attachment (`attachment_text`, when Tika is
active), and — with the renderer enabled — a screenshot of **every message that has an HTML
body, including nested ones** `[D3]`, each a separate artifact with its own `message_index`.
Rendering only the top-level message would be a choice made for the consumer, and a nested
message is often the one that matters.

### 13.2 `eml` carries original bytes

The `eml` artifact — of the top-level message and of every nested one — carries bytes **taken
from the input material**, never the result of reassembling a message from its parsed parts.
Where a part carried a transfer encoding, these are the bytes **after decoding**, because those
are the message. The hashes are computed from the same bytes `[D12]`.

The reason is practical: **a hash is the identity of the material.** A hash of a reconstruction
identifies what the service assembled, so it agrees neither with what a recipient saving the
message from their own mail client computes, nor with what this same service computes after its
serialising library changes — and recognising "this one came before" (§15) stops working
silently, with no signal at all. Reassembly is byte-neutral only for input that was already
canonical; every malformed shape is normalised, and at least one (a space before the header
colon) loses the header entirely (F1).

### 13.3 Serving

Downloading an artifact is **the only place where hostile material returns to a browser**, so
the response must not repeat anything the message said.

- **`Content-Type` is always `application/octet-stream`** — never the type declared by the
  sender nor the one detected from content. Serving `text/html` from the service's own origin
  is a script ready to run in its context.
- **`Content-Disposition: attachment` always**, with a **sanitised** filename: no control
  characters (a `CR`/`LF` injection breaks headers apart), no paths, encoded per RFC 6266 and
  trimmed to a sane length. The standard library does not strip paths for us (F4).
- **`X-Content-Type-Options: nosniff`**, so the browser does not guess the type on our behalf.

A consumer who wants to know the real type has `declared_mime` and `detected_mime` in the
dissection response — there they are data, not an instruction for a browser.

### 13.4 Lifetime

Artifacts are stored **ephemerally** under `dissect_id`, with a configured lifetime and
background sweeping. The service is not a store.

- **Artifacts live only inside the container.** A temporary directory inside the image,
  **recommended as `tmpfs`** — somebody else's correspondence has no reason to touch persistent
  storage, and on shutdown it disappears with the memory. Mounting a host volume is an option
  for deployments that deliberately want survival across restarts.
- **The lifetime is an UPPER BOUND, not a guarantee.** An artifact may vanish earlier, most
  simply through a restart, which wipes the store. Consumers are expected to fetch artifacts
  promptly and to treat both `ARTIFACT_EXPIRED` and `ARTIFACT_NOT_FOUND` as normal cases.
- **The service remembers only within the life of its process.** One model, three consequences:
  a restart wipes the store; an artifact created in a previous process life is **unknown**, not
  "expired" (404, not 410); and the store and its index are local to the instance, so several
  replicas need either routing that keeps a `dissect_id` on one instance or a shared directory.
  The 410/404 distinction costs no extra structure: the index exists anyway, because the
  service must know what to delete, and an expired entry stays in it as a tombstone for the
  rest of the process's life.
- **The service does not manage space.** No capacity limit, no eviction, no deleting someone
  else's artifacts to fit new ones. How much space the machine has is the responsibility of
  whoever runs it. It does, however, **handle a failed write**: the dissection still succeeds —
  the JSON with headers, candidates and links is valuable on its own — the affected entries
  carry `artifact_id: null`, and the response carries `artifact_store_failed` so the consumer
  knows this is an environment failure, not a property of the message.

## 14. Optional tools

**The service calls the tools, not the consumer.** The consumer sees one address and one
response; text extraction and rendering happen inside the dissection, before the response
returns. The deployment consequence is easy to miss: **the tools must be reachable for the
service, not for the consumer**, and they need access to nothing but it.

Both dependencies are **soft**: without them the service works and returns a correct, if
poorer, result. What is missing without each of them is visible in `tools{}`.

**Dependency states**, shared by both and with one meaning: `ok` — the tool answered; `down` —
could not connect, or it answered with an error; `timeout` — it exceeded its time limit;
`disabled` — there is no address in the configuration, so the tool does not exist for this
deployment; `skipped` — there is an address, but there was nothing to ask about (no document to
process, no HTML to render) `[D1]`. The distinction is deliberate: a consumer must tell "there
is no text because the document had none" from "there is none because nobody extracted it".

**One field, many calls — the worst wins.** Both tools are called repeatedly within one
dissection (Tika once per document, the renderer once per HTML-bodied message), and `tools{}`
has one field per tool. The **heaviest outcome** of the calls made in that dissection is
reported, in the order `down` > `timeout` > `ok` > `skipped` > `disabled` `[D5]`: two
successful renders and one exceeded limit give `timeout`, not `ok`. What succeeded
individually, the consumer reads from `artifacts[]` and from `attachments[].text_artifact_id` —
the aggregate field is a signal that something went wrong, not an inventory. A partial success
reported as a full one would be a silent failure.

### 14.1 `TIKA_URL` — text extraction from documents

- **Call:** `PUT <TIKA_URL>` with the attachment bytes in the body, `Accept: text/plain`,
  `Content-Type` = the attachment's type — the declared one, or the detected one when the
  declared type is not a `token/token` a request header can carry. This is the Apache Tika
  Server protocol and the `apache/tika` image works with no adapter.
- **What is sent:** only attachments of document types (PDF, office formats, RTF,
  OpenDocument) — not images, not archives, not executables. Size and time limits from
  configuration.
- **What is done with it:** the text returns as an `attachment_text` artifact, and candidates
  extracted from that text go into `observables` with the source `{kind:"attachment",
  part_index}` — **in the same, single list** as candidates from the message body. There is no
  second pass and no separate set to merge.
- **Without it:** `tools.tika` is `disabled` (no address), `skipped` (address present, no
  document in the message) or `down`/`timeout`; no `attachment_text` artifacts, no candidates
  from documents. The rest of the dissection is unchanged.

### 14.2 `SCREENSHOT_URL` — rendering the content to an image

- **The service does not render.** Rendering HTML is running someone else's code and has a
  different risk profile from parsing: a parser reads hostile material, a renderer runs it.
  Hence a separate component, chosen and isolated by whoever deploys it.
- **Call:** `POST <SCREENSHOT_URL>`, `multipart/form-data` with an `index.html` part (the
  message content) and parts for embedded resources; the response is image bytes (`image/png`,
  `image/jpeg` or `image/webp`). The shape matches Gotenberg's screenshot route, so that image
  works with no adapter; any other renderer needs a thin shim to this contract.
- Embedded resources are sent as asset parts named from the **part index**, never from the
  sender's filename, and the `cid:` references in the HTML are rewritten to those names. Remote
  URLs are left untouched; the renderer is expected to be configured not to load them.
- **Recommendations for the rendering component** (not a requirement of this service, but a
  deployment without them is imprudent): scripting disabled, no navigation and no fetching of
  remote resources, a fresh process per render, a hard time limit. Mail clients do not run
  scripts anyway, so a render without them is **more faithful** to what the recipient saw —
  this is not a trade-off between security and quality.
- **Without it:** `tools.renderer` is `disabled`, `skipped` (no message had HTML content) or
  `down`/`timeout`; no `screenshot` artifacts. The rest of the dissection is unchanged.

### 14.3 `GET /v1/health`

Returns `{ok, version, uptime_seconds, tools:{tika, renderer}, tools_checked_age_seconds,
registries:{public_suffix_list, file_extensions}, extra_file_extensions}` with status **200 whenever the service is
alive** — including when the optional dependencies do not answer. A dead Tika is not a failure
of this service, only a poorer mode of operation; if health depended on soft dependencies,
every mechanism that restarts unhealthy containers would kill a working service for someone
else's problems. States in `tools{}` mean the same as in the dissection response, except that
`skipped` does not occur, as there is no material to process — no address gives `disabled`.

**How health knows the dependency state: an on-demand probe with a short cache** `[D6]`.
Telling `ok` from `down` requires knocking on the tool, but probing on every call turns health
into a traffic amplifier: a mechanism asking every few seconds then knocks on both dependencies
continuously, and a hanging dependency lengthens the health response — which is exactly the
failure mode the paragraph above exists to prevent. So the probe fires **on demand, but no more
often than once per `HEALTH_CACHE_TTL_SECONDS`**, both dependencies in parallel, with its own
short `HEALTH_PROBE_TIMEOUT_SECONDS`, independent of the dissection budgets. The response
carries the age of the measurement in `tools_checked_age_seconds` (`null` when no dependency is
configured, so there was nothing to probe). Two edge conditions: a tool in state `disabled` is
**not probed at all**, and `POST /v1/dissect` **never reads this cache** — states in a
dissection come from calls made during that dissection.

## 15. Limits and time budgets

Hostile input is the assumption, so limits replace trust. All are configurable (§19).

| Variable | Default | What it bounds |
| --- | --- | --- |
| `MAX_MESSAGE_BYTES` | 50 MB | input size — hard rejection before parsing (`TOO_LARGE`) |
| `MAX_ATTACHMENT_BYTES` | 25 MB | one attachment after decoding — `truncated`, hashes computed anyway |
| `MAX_NESTING_DEPTH` | 5 | nesting depth |
| `MAX_MIME_PARTS` | 500 | number of MIME parts |
| `DISSECT_TIMEOUT_SECONDS` | 60 | the **whole** dissection, dependency calls included |
| `TIKA_TIMEOUT_SECONDS` | 20 | one text-extraction call |
| `SCREENSHOT_TIMEOUT_SECONDS` | 30 | one render |
| `HEALTH_PROBE_TIMEOUT_SECONDS` | 2 | one dependency probe from `/v1/health` — not from a dissection |
| `HEALTH_CACHE_TTL_SECONDS` | 10 | how long `/v1/health` may serve a remembered state |
| `MAX_INLINE_BODY_BYTES` | 256 KB | content in the response; above it, artifact only |
| `ARTIFACT_TTL_SECONDS` | 1800 | artifact lifetime (upper bound, not a guarantee) |
| `ARTIFACT_DIR` | `/tmp` | artifact store directory |
| `TIKA_URL`, `SCREENSHOT_URL` | empty | optional dependencies (empty = `disabled`) |
| `UNWRAPPERS` | empty | the unwrapper table (§10) |

**There is deliberately no limit on the sum of attachments:** the sum of decoded bytes cannot
exceed the input size, because transfer encoding only inflates — and the service does not
expand archives, so there is no path such a limit would protect. A parameter that never fires
is worse than its absence.

**A limit that protects against cost must be enforceable before the cost is paid** `[D13]`. The
number of parts and the nesting depth are established by a **cheap pass over the raw bytes,
before the tree is built**: a limit checked on a finished tree protects against the size of the
result but not against the work already done. A message of a million small parts is to be cut
during the scan, not after tens of seconds of parsing (F3).

**Exceeding `MAX_MIME_PARTS` or `MAX_NESTING_DEPTH` is not a request failure:** the service
dissects up to the limit and returns a partial result with `truncated`, exactly as with an
exceeded time budget. `TOO_LARGE` is reserved for input size, rejected before parsing.

**There are three time budgets, not one.** The dependencies have their own limits, because
otherwise one slow call eats the whole budget and topples a dissection that would otherwise
have succeeded. Exceeding a dependency limit → its state becomes `timeout`, the artifact it
would have produced is missing, **the dissection continues**. Exceeding the whole-dissection
limit → a partial result with `truncated`. The whole budget is meant to be larger than the sum
of typical calls: a renderer can need a dozen seconds to start its engine before it draws
anything.

**The whole budget is enforced at work-unit boundaries** — a message, an attachment, a single
dependency call — and not in the middle of parsing: the service checks the deadline between
units and stops before the next one, returning what it has computed `[D10]`. The asynchronous
model does not exempt us from this: a limit placed on an I/O operation cancels the wait but
does not interrupt parsing in progress, so without an explicit deadline `truncated` is
unimplementable, not merely imprecise.

**The boundary "this is not a message" is single and structural.** A message per RFC 5322 has
at least one `Name: value` line before the first empty line. Not even one → `UNPARSABLE` (§16),
rejected before dissection. At least one → we enter the dissection and **everything that falls
apart from there on is `malformed_mime`**, not an error. The boundary requires no particular
header: demanding `From` or `Date` would be policy, because messages without them exist. Nor is
it a heuristic over content (proportion of non-printable bytes, file signatures) — such guessing
would give different results in different implementations.

The boundary is decided **on the raw bytes**, not on what the parser returned: a line beginning
with `From ` is swallowed by the standard library as a Unix mbox envelope line, so a message
whose only header-looking line is `From : a@example.com` parses into zero headers with no defect
at all (F1b). Reading that as "no headers" would be right by accident here and wrong for a
genuine mbox export, which legitimately opens with an envelope line followed by real headers.

**Damaged MIME is normal input**, not an exception: flag `malformed_mime`, dissect what can be
dissected. The flag marks what **failed**, never what merely looks unappetising `[D23]`: a
message with one header and a binary body parses without a single fault and does not get it.
A flag that also fires on healthy material stops meaning anything — the consumer learns to
ignore it, and then it is missing for the case it exists for. The standard library is nearly silent about damage (F8), so both `malformed_mime`
and `attachment_unreadable` are defined by this service: the former when the raw header
disagrees with what was parsed or the structure does not close; the latter when the decoder
reports that the byte stream cannot be reconstructed faithfully.

**An oversized attachment and a damaged attachment are two different events** with two
different flags. Oversized: the material was healthy, the service chose not to go further — an
entry in `attachments[]` with no artifact (`artifact_id: null`) but **with all three hashes**,
and the flag `truncated`. The consumer gets the means to check a file the service does not
serve. Damaged: the bytes cannot be read, so the hashes are `null`, both ids are `null`, and
the flag is `attachment_unreadable`.

**What that costs in memory, stated plainly.** The hashes are computed in one pass over the
decoded bytes and the bytes are then dropped, but the service is **not** `O(1)` in memory and
sizing a container as though it were will get it killed. The whole input is held at once — the
`UNPARSABLE` gate and the `source` hashes both need it — and a decoded attachment is held
while it is hashed and written. Peak memory for **one request** is therefore on the order of

> `MAX_MESSAGE_BYTES` (the input) + the parser's own representation of it + the encoded span
> of the largest part + `MAX_ATTACHMENT_BYTES` (its decoded form)

**Measured at the default limits: 452 MB peak RSS** for a 47 MB message carrying a 24 MB
attachment, in a process whose interpreter and imports account for 43 MB of that. The largest
single contributor is the standard library's own representation of the message, not our
copies. **Concurrent requests multiply this figure** — the service is single-process and does
not queue, so two dissections of that size at once want roughly twice the memory.

**The third factor is the tool fan-out.** Calls to the optional tools run concurrently, up to
**`MAX_TOOL_CONCURRENCY` = 4**, and each in-flight call holds the attachment it is sending.
This is a constant in the code rather than a variable: the configuration surface of §19 is
closed, and a parameter nobody asked for is worse than its absence. It is named here because a
deployment sizing a container needs all three factors — input size, concurrent requests, and
concurrent tool calls — and cannot derive the third from anywhere else.

Size the container from the limits you actually configure, not from the typical message.

**Strings that cannot be serialised are scrubbed, and a scrub that loses anything is
reported.** One 8-bit byte in a header can produce a lone surrogate that makes the JSON response
raise inside the framework (F5, F17). Such strings are scrubbed at the response boundary: the
escaped bytes are read back as UTF-8, as the header registry reads them. Where they decode, the
string is what the sender wrote and there is nothing to report; where they do not, U+FFFD stands
in, the returned string is no longer what stood in the material, and the response carries
`encoding_fallback` `[D20]` — the flag already means exactly that (§5.1), so the contract needs
no extension.

## 16. Error contract

One envelope with a machine-readable code: `{ok:false, dissect_id, error:{code, message}}`.
`dissect_id` is present also on failure — without it the consumer cannot correlate the error
with the request.

| Code | HTTP | When |
| --- | --- | --- |
| `BAD_REQUEST` | 400 | no message on input, empty body, unknown `Content-Type` |
| `TOO_LARGE` | 413 | message over the input limit — rejected before parsing |
| `UNPARSABLE` | 422 | input contains **not one valid header** before the first empty line (§15) |
| `ARTIFACT_NOT_FOUND` | 404 | unknown `dissect_id`/`artifact_id`, including an artifact from a **previous process life**; also a request for a listing |
| `ARTIFACT_EXPIRED` | 410 | the artifact was created **in the current process life** and its lifetime passed |
| `INTERNAL` | 500 | a failure on the service's side |

Telling 404 from 410 is part of the contract: the consumer is to know whether they got the
identifier wrong or came too late.

A result cut short by the time limit returns as **HTTP 200 with `ok:true`** and the `truncated`
flag — it is a partial result, not a failed request. Artifacts written before the cut remain
available and are listed in `artifacts[]`; those that were still to be created are not. The
consumer recognises the situation by the flag, not by the status.

**Problems with optional dependencies are not errors** — they go to `tools{}` and do not change
the response status.

## 17. Determinism — the overriding criterion

The same message, with the same limits, the same availability of optional dependencies and
**the same registry versions — the extension supplement of `[D22]` included, which is why it
is folded into the reported version** (§12) — yields the same result, regardless of the moment
and the order of calls. This includes **the order of elements in arrays**: `observables[]`, `links[]`,
`resources[]`, `attachments[]` and `artifacts[]` follow the order of occurrence in the
material, not the order in which the implementation happened to find them.

Excluded from the requirement is the **composition** (not the order) of what depends on the
environment: `dissect_id` and `artifact_id` (random by definition), `tools{}`, the presence of
tool-dependent artifacts (`screenshot`, `attachment_text`) and of the `observables[]` entries
derived from them, the value of `attachments[].text_artifact_id`, and **those flags that
describe the environment**: `artifact_store_failed` and `truncated` arising from a time
overrun. Flags that describe the **material** — `malformed_mime`, `encoding_fallback`,
`attachment_unreadable` — are fully deterministic and subject to the requirement like
everything else.

## 18. Testing contract

Test material is **synthetic messages only**. The repository does not and will not contain
anyone else's correspondence, and the tests do not reach for public mail corpora. The decision
is deliberate and has three reasons, so that nobody reverses it later: such collections contain
personal data of living people (parts of the Enron corpus were withdrawn for exactly that
reason), spam archives and company mailboxes **contain real malware** (hundreds of executables
were counted in the Enron corpus), and their licences are often unclear. Above all, they are a
**poor instrument for this task**: we are testing resilience to strange MIME structure, and a
corpus hits that by accident, if at all. A synthetic message aims at a specific requirement and
is repeatable.

The suite is **offline by default** — no network, no dependency reachable — and CI depends on
that. Sixty-six numbered acceptance cases are listed in
[`spec-coverage.md`](spec-coverage.md), each mapped to the section it exercises.

**Resilience is a separate species of test:** a correct synthetic message is damaged
programmatically and the service is required not to fall over. Mutations cover at least:
truncation at a random offset, removed and duplicated headers, a header with no colon and no
value, broken `base64` and `quoted-printable`, a charset declaration disagreeing with content,
missing and mismatched `boundary`, empty parts, nesting deeper than the limit, very long lines,
control characters and a NUL byte, bytes above 0x7F in header values, mixed `CRLF` and `LF`.

The criterion is single and hard: **no mutation may raise an unhandled exception or exceed the
time limit.** Acceptable outcomes are a correct response (however poor, with `malformed_mime`
or `truncated`) or an error envelope with a code from §16. The mutation generator takes a
random seed and reports it, so that every case found can be reproduced with one command.

**A fuzzer finding does not end its life as a seed number.** Every input that toppled a
dissection or exceeded the time limit **stays in the suite as a permanent test with the
material saved** `[D18]`. Externally reported defects enter the same way: a minimal repro
becomes another test, not an entry in an issue history.

## 19. Configuration

Configuration is **environment variables only** (§15): the addresses of the optional
dependencies, the full set of limits, the artifact lifetime and directory, and the unwrapper
table. The image starts with sensible defaults — **no variable is required to run it**.

A configuration error kills the process at startup rather than being ignored: the settings
object is built eagerly, before the server binds.

## 20. Logging

JSON lines on stdout, no log files (rotation is the container runtime's job). One event line
per dissection, carrying `dissect_id`, input size, message count, flags and duration.

**No message content and no `artifact_id` are ever logged** (§4). `dissect_id` may be logged:
on its own it grants access to nothing, because a download needs both identifiers.

## 21. Versioning

The `/v1` path is part of the contract. Adding a field is a backwards-compatible change;
changing the meaning of a field, or narrowing or extending a closed value set, is not, and
requires `/v2`. The container image carries a version tag; `latest` is not a contract.

## 22. Decision record

Approved by the maintainer, 2026-09-17.

**Contract**

- **[D1] No address → `disabled`; address present with nothing to do → `skipped`.** The
  distinction is the reason these states exist at all (§14).
- **[D2] Unwrappers apply to `resources[]` as well, and both categories carry
  `unwrap_failed`** — otherwise `resources[].rewritten_from` would be a field that is never set.
- **[D3] A screenshot is rendered for every message with an HTML body, including nested ones**,
  each with its own `message_index`.
- **[D4] `body.text_from_html` has its own inline threshold and its own artifact**
  (`body_text_from_html`) — the conversion is a rule of this service and cannot be reproduced
  from `body_html`.
- **[D5] `tools{}` reports the heaviest outcome**, in the order `down` > `timeout` > `ok` >
  `skipped` > `disabled`.
- **[D6] `/v1/health` probes on demand behind a short cache**, both dependencies in parallel,
  never probing a `disabled` tool; `POST /v1/dissect` never reads that cache.
- **[D14] `sources[]` lists distinct places, `occurrences` counts every occurrence.** With no
  offsets in the schema, "all the places it occurred" can only mean distinct places.
- **[D20] Unserialisable strings are scrubbed at the response boundary, and a scrub that
  substitutes anything is reported as `encoding_fallback`** — never silently; one that loses
  nothing is not reported at all. Amended for 0.2.0: until then every scrub was reported,
  including a lossless one, which made the flag fire on raw UTF-8 in an address but not on the
  same bytes in a subject.

**Implementation**

- **[D7] The indicator grammars are written in this project**, so the taxonomy is ours and no
  external tool's identifiers leak into the contract.
- **[D8] Registries are snapshots baked into the image**; where a registry has no release
  number, its version is the snapshot date plus a digest of its content; public-suffix matching
  is implemented here rather than taken from a package that would carry its own snapshot.
- **[D9] Scan order within a message: headers → `text/plain` → HTML in document order →
  document texts by ascending `part_index`**, with an append-only collector, so the
  deterministic core of `observables[]` does not move when a tool is absent.
- **[D10] Asynchronous service; the whole-dissection budget is an explicit deadline checked at
  work-unit boundaries**, because an I/O timeout cannot interrupt parsing.
- **[D11] The MIME tree comes from the standard library with `policy.compat32`**, plus a
  self-checking byte-range locator for `message/rfc822` parts and a cheap pre-pass for limits.
  `policy.default` costs ~10× per part (F3) and neither policy can enforce a part limit before
  doing the work.
- **[D12] The `eml` artifact carries original bytes, never a reconstruction**; hashes are
  computed from those bytes. Reassembly is byte-neutral only for already-canonical input (F1).
- **[D13] Part and nesting limits are established before the tree is built; exceeding them
  yields `truncated`, not an error.** `TOO_LARGE` stays reserved for input size.
- **[D15] HTML is parsed with the standard library's `html.parser`** — no C extension reading
  the one input class guaranteed to be hostile, and no tree repair that varies with a library
  version (F10).
- **[D21] Only the ICANN section of the public suffix list is loaded**, and the section is
  named in the version string, because which section is in use changes recognition and a
  version number alone does not reveal it (§12).
- **[D23] A flag describes a failure, not an appearance.** `malformed_mime` is raised from
  what actually failed to parse — the parser's own defects, or our view of the bytes
  disagreeing with its view of the tree — and never from material that is merely binary or
  unusual. A flag that fires on healthy input teaches consumers to ignore it.
- **[D22] The extension registry has a configurable, empty-by-default, additive supplement**
  (`EXTRA_FILE_EXTENSIONS`). Both available registries are keyed by media type and so know
  none of the script formats (F13); shipping our own list of them would make the service carry
  a point of view. The mechanism is ours, the content is the deployment's — and because it
  changes recognition, it is reported in `/v1/health` and folded into the registry version.

**Delivery**

- **[D16] The first image tag is `v0.1.0`, and `1.0.0` is released when the consumer says
  it is.** The stability promise is carried by `/v1` in the path. The major version marks the
  consumer's judgement that the contract holds on real material — not a date, and not a count
  of defect rounds — so until the consumer says so, releases stay below `1.0.0`.
- **[D17] `mypy --strict` and a 90% coverage floor**, a deliberate exception to the house
  pattern for service repositories, because the contract is large and closed. Above both:
  **every assertion must be able to fail**, verified by breaking the behaviour it describes.
- **[D18] Every fuzzer finding becomes a permanent regression test with the material saved.**
- **[D19] The example `compose.yml` pins both tool versions, uses the minimal Tika variant, and
  demonstrates isolation** — a network with no route out for all three containers and the
  renderer's hardening flags. Since this specification cannot require hardening of a component
  it does not control, the example is the only place where the recommendation becomes visible.

## 23. Explicitly out of scope (v1)

- Authentication (a layer in front of the service, §3).
- Expanding archives, recursively or otherwise.
- Any reputation, DNS or resource-fetching lookup — **permanently** out, per §2.
- Store capacity management: quotas, eviction, deleting other dissections' artifacts (§13.4).
- A per-call tool state on each attachment: the mixed case is derivable from
  `text_artifact_id` together with the aggregate state, and it would extend a closed schema for
  a third time. A candidate for `/v2` if practice shows it hurts.
- Chunked intake of the input message: the `UNPARSABLE` gate and the `source` hashes need the
  whole input first.
