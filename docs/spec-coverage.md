# Coverage map — requirements and acceptance cases

Every functional requirement and every acceptance case has a home in
[`SPEC.md`](SPEC.md) and a test that proves it. This table is what makes a lost requirement
visible: a row with no section is a gap in the specification, and a row with no test is a
promise nobody checks.

The `Test` column is filled in as the implementation stages land; `stage N` marks a case whose
test does not exist yet. `SPEC.md` is the authority — where this map and the specification
disagree, the specification is right and this file is stale.

## Functional requirements

| # | Requirement | SPEC.md |
| --- | --- | --- |
| 1 | Descend into nested messages, including transport-encoded ones | §6.2 |
| 2 | Decode before reading (never scan raw bytes) | §7.2 |
| 3 | Handle character encodings; fall back rather than abort | §7.2 |
| 4 | Split parts into roles by one rule | §6.3 |
| 5 | Decompose every address header in full | §7 |
| 6 | Decompose `Received` into a hop chain | §7 |
| 7 | Report declared type next to detected type | §7.1 |
| 8 | Compute md5/sha1/sha256 for the source and every attachment | §5, §13.2, §15 |
| 9 | Provide a deterministic text rendering of HTML | §9.3 |
| 10 | Decompose `Authentication-Results` into every method present | §7 |
| 11 | Return all HTML addresses in two disjoint categories | §9.1 |
| 12 | Unwrap rewritten addresses, in links and resources alike | §10 |
| 13 | Extract indicator candidates from all four sources | §11 |
| 14 | Extract addresses only where they are addresses (structural rule) | §9.2 |
| 15 | Expose artifacts, ephemerally, with a lifetime | §13 |
| 16 | Return original bytes, never a reconstruction | §13.2 |

## Acceptance cases

| # | Case | SPEC.md | Test |
| --- | --- | --- | --- |
| 1 | simple single-part `text/plain` | §6.3 | stage 2 |
| 2 | `multipart/alternative` with HTML and text | §6.3 | stage 2 |
| 3 | nested `message/rfc822` carries the original, not the envelope | §6.2 | stage 2 |
| 4 | two nestings in one message, and a two-level nesting | §6.2 | stage 2 |
| 5 | long URL broken by `quoted-printable` is recovered whole | §7.2 | stage 3 |
| 6 | link rewritten by a reversible wrapper | §10 | stage 3 |
| 7 | link rewritten by a wrapper outside the table — unchanged, no network call | §10 | stage 3 |
| 8 | RFC 2047 headers and an 8-bit body disagreeing with its declaration | §7, §7.2 | stage 2 |
| 9 | damaged MIME → `malformed_mime` plus a partial result | §15 | stage 2 |
| 10 | oversized attachment → `truncated`, rest of the dissection complete | §15 | stage 2 |
| 11 | `sha256` of the message and attachments matches an independent computation | §13.2 | stage 2 |
| 12 | full dissection with no name resolution and no route out | §2 | stage 1 |
| 13 | optional dependencies disabled → `tools{}` says so, result complete otherwise | §14 | stage 1 / 5 |
| 14 | artifact past its lifetime, without a restart → `ARTIFACT_EXPIRED` (410) | §13.4 | stage 5 |
| 15 | two nestings with HTML each → two `body_html` artifacts, different `message_index` | §13.1 | stage 2 |
| 16 | attachment with broken encoding → `attachment_unreadable`, hashes `null` | §15 | stage 2 |
| 17 | message over the input limit → `TOO_LARGE` (413), no parse attempted | §15, §16 | stage 1 |
| 18 | request for an artifact listing → 404, never an enumeration | §4 | stage 1 |
| 19 | artifact after a restart → `ARTIFACT_NOT_FOUND` (404) | §13.4 | stage 2 |
| 20 | the same input through both channels → identical results | §4 | stage 1 |
| 21 | `mailto:` anchor and `cid:` resource → both present, `host: null`, `cid_part` set | §9.1 | stage 3 |
| 22 | remote image and an anchor with the same address → both lists, one observable | §11 | stage 4 |
| 23 | URL with `userinfo` → `host` and `userinfo` split correctly | §9.1 | stage 3 |
| 24 | the same address five times → one entry, `occurrences: 5`, complete `sources[]` | §11.3 | stage 4 |
| 25 | defanged address → `value` re-armed, `value_raw` original, `defanged: true` | §11.3 | stage 4 |
| 26 | `raport.zip` → two candidates; `faktura.pdf` → only `filename` | §11.3 | stage 4 |
| 27 | IDN host in uppercase → punycode and lowercase in `value`, path untouched | §11.3 | stage 4 |
| 28 | private address `10.0.0.5` → present, not filtered | §11.3 | stage 4 |
| 29 | a binary file sent as a message → `UNPARSABLE` (422) | §15, §16 | stage 1 |
| 30 | one valid header and garbage after it → 200 with `malformed_mime` | §15 | stage 1 |
| 31 | artifact write impossible → success, `artifact_id: null`, `artifact_store_failed` | §13.4, §8 | stage 2 |
| 32 | `README.md`/`raport.zip` ambiguous; `faktura.pdf`/`example.com` not | §11.3 | stage 4 |
| 33 | `wersja.1.2` → no `domain` candidate | §11.2 | stage 4 |
| 34 | `bit.ly/xyz` and `www.example.com` → `url` plus their hosts as `domain` | §11.2 | stage 4 |
| 35 | email address in content → `email` plus its domain as `domain` | §11.2 | stage 4 |
| 36 | `/v1/health` → 200 with dependencies off, all fields, registry versions | §14.3, §12 | stage 1 |
| 37 | `multipart/mixed` with two `text/plain` → first is the body | §6.3 | stage 2 |
| 38 | `multipart/related` with `alternative` inside and a `cid:` image | §6.3, §9.1 | stage 3 |
| 39 | two attachments with identical names → distinct `part_index` | §5.2 | stage 2 |
| 40 | wrapper inside a wrapper → unwrapped to a fixed point | §10 | stage 3 |
| 41 | entry matches but the target cannot be extracted → `unwrap_failed: true` | §10 | stage 3 |
| 42 | malformed `UNWRAPPERS` → the service does not start | §10, §19 | stage 1 |
| 43 | address decomposition across `From`, `To`, `Reply-To` | §7 | stage 2 |
| 44 | three-hop `Received` chain, `null` where the header was incomplete | §7 | stage 2 |
| 45 | `Authentication-Results` with four methods including a non-standard one | §7 | stage 2 |
| 46 | `headers` completeness: custom and repeated headers | §7 | stage 1 |
| 47 | declared type ≠ detected type, with no comment from the service | §7.1 | stage 2 |
| 48 | `charset_declared` ≠ `charset_used`, `encoding_fallback`, content readable | §7.2 | stage 2 |
| 49 | `text_from_html` with and without a `text/plain` part | §9.3 | stage 3 |
| 50 | inline threshold for `html` and for `text_from_html` | §8 | stage 3 |
| 51 | all three hashes for the message and every attachment | §13.2 | stage 2 |
| 52 | working Tika → `attachment_text`, candidates with an `attachment` source | §14.1 | stage 5 |
| 53 | working renderer → `screenshot` artifact with `message_index` | §14.2 | stage 5 |
| 54 | whole-dissection budget exceeded → 200, `ok: true`, `truncated` | §15 | stage 5 |
| 55 | unknown `artifact_id` with a valid `dissect_id` → 404 | §16 | stage 1 |
| 56 | candidates from headers carry `header_name` and `header_index` | §11.1 | stage 4 |
| 57 | artifact response headers: octet-stream, sanitised filename, nosniff | §13.3 | stage 2 |
| 58 | mixed tool outcome → worst wins (`timeout`), per-item links still correct | §14 | stage 5 |
| 59 | nested message screenshot → two `screenshot` artifacts | §13.1, §14.2 | stage 5 |
| 60 | rewritten resource → target in `href`, `rewritten_from`, `unwrap_failed` on failure | §10 | stage 3 |
| 61 | health and dependencies: `disabled` with no traffic, `down`, one probe per TTL | §14.3 | stage 1 / 5 |
| 62 | stable core of `observables[]` with and without document extraction | §11.1 | stage 5 |
| 63 | nested original byte-for-byte, hash matching an independent computation | §13.2 | stage 2 |
| 64 | transport-encoded nesting → a parsed message, `eml` after decoding | §6.2 | stage 2 |
| 65 | part count far over the limit → `truncated` in scan time, no full tree | §15 | stage 2 |

## Resilience

| Requirement | SPEC.md | Test |
| --- | --- | --- |
| No mutation raises an unhandled exception or exceeds the time limit | §18 | stage 6 |
| The mutation seed is reported and every finding becomes a permanent test | §18 | stage 6 |
| Determinism, including array order | §17 | stage 6 |
