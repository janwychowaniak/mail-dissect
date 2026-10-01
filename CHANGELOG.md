# Changelog

The release notes are the annotated tag messages; this file carries the same notes where they
can be read without git, together with the image digest each version was published under, and
corrections to them.

**A tag is never pushed again, not even to fix its message.** Pushing it runs the release again
and can publish the same version under a different digest, which breaks the one property a
pinned deployment stands on. A wrong line in a tag message is corrected here instead, as an
erratum that says what the tag claims and what is true.

## Known defects

Defects that are known and not fixed yet, in the release this file was shipped with. Each has a
saved message in `tests/regressions/` and a test in `tests/test_known_defects.py` that states
what the contract asks for and is marked as an expected failure, strictly: once the defect is
fixed the suite fails until the mark and the entry here are removed, so an entry cannot outlive
its defect.

- **A defanged form directly after a hyphen or a period is not returned** (SPEC §11.3).
  `-host[.]example[.]net`, `-hxxp://example[.]net/x`, `-user[at]example[.]net` and
  `-192[.]0[.]2[.]1` yield no candidate, and neither does `.host[.]example[.]net`. The same
  forms after a space — `- host[.]example[.]net` — are re-armed and returned with
  `defanged: true`. In every release since 0.1.0, measured on the published images.
  Saved as `2026-10-01-defanged-after-a-hyphen-or-a-period.eml`.

## 0.5.0 — 2026-10-01

`ghcr.io/janwychowaniak/mail-dissect@sha256:1b80fe5c240117ea0ac2ded52f7ff43b734bd1f42a39ccb05b0ee0953b49736e`

A period or a hyphen that touches an IPv4 address is now taken for punctuation, unless a label
character — a letter, a digit or an underscore, in any script — continues on its far side
(SPEC §11.2, `[D26]`). Until now either mark, on either side, ruled the address out whatever
stood beyond it, so an address that ended a sentence was not returned. A label character next to
the address still rules it out, and so does one beyond the mark: a host name that begins with
four numbers is still that host name.

The `/v1` paths, fields and value sets are unchanged. What moves is `observables[]` for a
message with an IPv4 address next to a period or a hyphen — in a header, a text body, an HTML
body and the text extracted from a document alike. Measured on the same inputs against 0.4.0:

**Changes:**

- an address before a period — where the period ends a sentence, a line or the text, or is
  itself followed by a bracket, a comma or further periods: returned, without the period; it
  was not
- an address after a period or an ellipsis: returned; it was not
- an address after a hyphen, as in a list, and before a hyphen that is followed by a space or a
  line break: returned; it was not
- a range: `a- b` and `a -b` return both ends, where they returned one; `a...b`, `a..b` and
  `a--b` return both, where they returned none
- an address ending in `.123` or `.210` next to one of these marks: an `ip` candidate; it was a
  `filename` candidate, because those two numbers are file extensions in the registry
- an address that was already returned from another place in the message: still one entry, with
  a higher count; when the newly recognised occurrence comes first, the entry stands there,
  takes its `value_raw` and `defanged`, and lists that place first in `sources` — the other
  places stay listed
- an address, a hyphen and a line break, or an address and two hyphens, and then the rest of a
  host name: the address and the rest of the name; it was the rest alone after the line break,
  and the whole name with the two hyphens

**Unchanged:**

- an address next to a space, a comma, a semicolon, a colon, a bracket, a quote or a port
- `192.0.2.1.example.net`, `192.0.2.1-static.example.net` and `192.0.2.1.Next`: the domain
  candidate they were, and no address
- five numbers, a version suffix, a word joined on by a hyphen or a period (`192.0.2.1.5`,
  `192.0.2.1-rc1`, `word-192.0.2.1`, `end.192.0.2.1`), also after a non-ASCII letter or an
  underscore: no address
- a range with a bare hyphen, `a-b`: neither end
- a range with ports, with prefix lengths, or after an IPv4-mapped IPv6 address: the left end
  only
- an IPv6 address: a period before it rules it out, a period or a hyphen after it does not
- four numbers a parser refuses (`999.1.1.1`), before a period or not
- a defanged address before a period: returned, as it was; a defanged form directly after a
  hyphen or a period: not returned, in any grammar — a known defect, listed above
- domains, URLs, email addresses and hashes next to a period or a hyphen
- every message with no IPv4 address next to a period or a hyphen: identical responses; and in
  every message, everything outside `observables[]`

Also in this release: this file lists the defects that are known and not fixed, each with a
saved message and a test that fails once it is.

Verified against `apache/tika:3.2.3.0` and `gotenberg/gotenberg:8.37.0`.

## 0.4.0 — 2026-10-01

`ghcr.io/janwychowaniak/mail-dissect@sha256:2405d4b2d6a350a07fdd375421711f73b513b6660dc7d68ae40f54fd6b3fb577`

An address entry with no domain is now read once more (SPEC §7, `[D25]`). A whole address
written inside quotes — `From: "Name <address>"` — is, by the grammar, one quoted local part with
no domain, and until now its entry was an `address` holding the entire quoted string, next to
`domain: null`. The local part is now given to the same parser once, and the entry becomes what
that yields only when it is exactly one mailbox with a domain and the parser reports no defect.
Anything less clean leaves the entry exactly as it was, and an entry that has a domain is never
read again.

The `/v1` paths, fields and value sets are unchanged. What moves is `addresses{}` for an entry
that had no domain, in every address header and at every message level. Measured on the same
inputs against 0.3.0:

**Changes:**

- `"Name <address>"`: `display_name`, `address`, `local_part` and `domain` are the mailbox written
  inside the quotes; they were null, the quoted string, its content and null
- `"address"`: the address, with no display name
- a quoted entry inside a list: that entry alone changes
- a quoted word joined to an atom by a dot (`"a@b".c`): the one local part the parser makes of
  it, read as an address

**Unchanged:**

- `headers{}`: the value with its quotes, as written
- text after the address inside the quotes, two addresses inside the quotes, a name alone: the
  entry as it was, with `domain: null` — the service does not cut an address out of a string
- `"address" <other address>`: the display name stays what it is and the address is the other one
- every entry that has a domain, and every message with no such entry: identical responses
- `observables` and `flags`

The seven shapes are pinned on the interpreter the image ships, where the parser returns one
mailbox on 3.13.12 and two on 3.13.15 for the shapes that are left alone; the verdict is the
same on both.

Verified against `apache/tika:3.2.3.0` and `gotenberg/gotenberg:8.37.0`.

## 0.3.0 — 2026-09-30

`ghcr.io/janwychowaniak/mail-dissect@sha256:164d4efc570ee1a5b0103d0e806ac9e0af476793aada0406e4ea3c685181b2c5`

A header is now unfolded before anything reads it (SPEC §7, `[D24]`). Where a header was broken
across lines is not part of its value (RFC 5322 §2.2.3): the line break is removed and the white
space after it is kept, whether the break is CRLF or a bare LF, in the headers of a message, of
a part and of a nested message alike. Until now the break stayed in the value.

`[D24]` also says what `headers{}` is: the parsed view of a header — unfolded, RFC 2047
decoded, a structured header as the parser renders it — while the `headers` artifact is the
record of how it was written. SPEC §7 names the structured headers.

The `/v1` paths, fields and value sets are unchanged. What moves is what a **folded** header
yields. Measured on the same inputs against 0.2.0:

**Changes, for a folded header:**

- `addresses`: an address header is decomposed; it was one entry of nulls. A list folded after
  its comma yields every address.
- `headers`: an address header is decoded and rendered; it was the raw value, encoded-words and
  line break included
- `headers`: any other header loses the line break and keeps the white space after it
  (`Subject`, `Received`, `Authentication-Results`, …)
- `headers`: two encoded-words either side of a fold are joined, as RFC 2047 §6.2 says; the
  break and the white space stood between them
- `headers`: `Content-Type` keeps its parameters; it ended at the semicolon
- `observables`: candidates are read from the unfolded value, so a name cut between two
  encoded-words is one candidate; its second half used to be reported as a candidate of its own
- `flags`: an address header with an encoded-word that does not decode raises
  `encoding_fallback`, as the same header on one line already did
- `mime_parts`, `attachments`: `filename` and `content_id` no longer carry a line break that
  was folded inside the value
- `received`, `auth`: a `Received` timestamp, and a quoted parameter of
  `Authentication-Results`, no longer carry a line break that was folded inside them. Every
  other field of a hop or of a result is a single token and was already right.

**Unchanged:**

- a header written on one line: every response is identical
- the MIME tree, the bodies, and the `eml` and `headers` artifacts, which carry the original
  bytes, folds included

Also in this release: the fuzzer folds header lines, and CI and the release workflow run the
header expectations inside the image, on the interpreter that is published.

Verified against `apache/tika:3.2.3.0` and `gotenberg/gotenberg:8.37.0`.

## 0.2.0 — 2026-09-23

`ghcr.io/janwychowaniak/mail-dissect@sha256:5c6b8c13c2680f9bc43ab7d742ae7c05fdfa9326a99936e9605532bf7b8614bf`

`encoding_fallback` now has one definition (SPEC §5.1): it fires when, and only when, the
service could not take the material's word for how it is encoded, or had to substitute
something in order to read it. `[D20]` is amended to match: a scrub that loses nothing is no
longer reported.

The `/v1` paths, fields and value sets are unchanged. What moves is which inputs raise the flag.
Measured on the same inputs against 0.1.1:

**Loses `encoding_fallback`** (read without loss, so nothing to report):

- raw UTF-8 (RFC 6532) in an address header: display name or address
- raw UTF-8 in a part's `Content-ID`, `Content-Type`, `Content-Disposition`, or quoted filename
- raw UTF-8 in a part's `Content-Transfer-Encoding` (`malformed_mime` stays)

**Gains `encoding_fallback`** (a declaration not taken, or a substitution):

- an RFC 2047 encoded-word whose charset cannot be looked up, in any header of a message or in
  an attachment's filename
- an RFC 2047 filename whose bytes do not decode in its charset
- an RFC 2231 filename (`filename*=` / `name*=`) whose charset cannot be looked up, or whose
  bytes do not decode in it

**Unchanged:**

- a lone 8-bit byte in any header or part field still flags
- a broken encoded-word in a header still flags (since 0.1.1)
- raw UTF-8 in a `Subject` or other unstructured header still does not
- a part's `charset=` that cannot be resolved still flags, UTF-8 or not
- ASCII-only material never flags

Also in this release: the large-field test exercises a plain form field, and the README no
longer suggests a looser renderer allow-list than `compose.yml` uses.

Verified against `apache/tika:3.2.3.0` and `gotenberg/gotenberg:8.37.0`.

**Erratum.** The v0.2.0 tag message also says that "the fuzzer's nightly long run executes for
the first time". It did not start in 0.2.0: that fix shipped before 0.1.1, in `f3eb2f5`.
Corrected in `9d41b97` and here; the tag is left as published.

## 0.1.1 — 2026-09-23

`ghcr.io/janwychowaniak/mail-dissect@sha256:cc697396bb70ee38ea8d688750c6a385cbbaf029b91caf1fa967c503ee5cba92`

A patch release for one defect: in 0.1.0 a byte above 0x7F in any header of a message — a lone
8-bit byte or valid UTF-8 — was a 500, and so were the same bytes in a part's `Content-ID` or
transfer encoding, or, with Tika configured, in a document's declared type (F17).

The contract is unchanged. Such a header is now dissected, a byte that had to be replaced is
reported as `encoding_fallback` as SPEC §7.2 and `[D20]` already said, and the fuzzer puts these
bytes into headers from now on.

Verified against `apache/tika:3.2.3.0` and `gotenberg/gotenberg:8.37.0`.

## 0.1.0 — 2026-09-18

`ghcr.io/janwychowaniak/mail-dissect@sha256:1f773c29ddcea0ca33a5b4247e9b181dee09343fc54cf1d103f473602e329ef0`

The first release of the contract in `docs/SPEC.md`: a deterministic structural dissection of
one email message over HTTP, with the large parts as ephemeral artifacts, and no judgement about
any of it.

All 66 acceptance cases pass, plus a seeded mutation fuzzer, a determinism check with
hand-reviewed vectors, and a container job that proves the service works with no route out.

Verified against `apache/tika:3.2.3.0` and `gotenberg/gotenberg:8.37.0`.

0.1.0 rather than 1.0.0 on purpose: the `/v1` path already carries the stability promise, and
the contract has not yet met a consumer other than its author.
