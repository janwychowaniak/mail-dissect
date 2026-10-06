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

None at the moment.

## 0.7.0 — 2026-10-06

`ghcr.io/janwychowaniak/mail-dissect@sha256:d898bf77ad9a7d15cb761b6764535574274067765a0ecc4cb2df6ea4e770611a`

Image Id `sha256:a6d3867da7165615fe916efbd985a08cb1c041bcad4e0de686695cb2aea9eaa6`, after a pull
and after `docker load` of the release file alike. Python 3.13.16.

A message can no longer hold the service: the work after parsing runs off the event loop, so
`/v1/health` is answered while a message is dissected; the deadline is asked inside a
dissection, not only after it; what was quadratic in the length of a run is linear; and a run, a
header, a part's parameters, the header fields and each list of a response have a bound, past
which the response says `truncated` (SPEC §14.3, §15, `[D29]`, `[D33]` to `[D37]`). A defanged
form is now read as the text it stands for (`[D28]`), and a URL in text by RFC 3986's two
grammars, with its host read as labels (`[D31]`, `[D32]`); a value derived from a URL is checked
against its type (`[D30]`).

The `/v1` paths, fields and value sets are unchanged. What moves is `observables[]`, `flags`,
`headers{}` and `addresses{}` for a header past its length, `mime_parts[]`, `attachments[]` and
`artifacts[]` for a part header past 8,192 characters and for a nested message written out
again, and what the renderer is sent. Measured on the same inputs against 0.6.0 — 38 inputs
chosen for these notes and 3,719 others: the messages the test suite sends, the saved ones, the
golden samples, and generated text, HTML, headers and MIME trees — every difference attributed
to the commit that made it:

**Availability:**

- `/v1/health` is answered during a dissection: while 50,001 links were dissected for 7.6 s it
  answered 65 times, the slowest in 0.62 s; on 0.6.0 it waited 9.4 s, the whole dissection
- the deadline is asked between messages, between headers, before each chunk of a scan and
  inside the HTML scan; a message reached after it is returned whole with no candidates. With
  `DISSECT_TIMEOUT_SECONDS=2`, the 50,001 links took 4.1 s and gave no candidates; 0.6.0 took
  9.4 s, gave all of them and said `truncated` all the same. Work between two of those points
  runs to its end, so a response can still come after the budget
- inputs that took seconds or minutes, now a fraction of a second: each a single request to the
  published 0.6.0 image and to this release's:

  | Input | 0.6.0 | 0.7.0 |
  | --- | --- | --- |
  | 192,000 characters of base64 in one line | 78.4 s | 0.09 s |
  | 100,000 characters of `a-` | 344 s | 0.42 s |
  | 200,000 characters of `a[.]` | 47.2 s | 0.14 s |
  | a header of 29,000 characters of `+1` | 32.8 s | 0.06 s |
  | a URL followed by 200,000 `}` | 77.9 s | 0.13 s |
  | 25,000 `url(` in a `<style>` | 57.6 s | 0.08 s |
  | `Authentication-Results`, a run of 64,000 | 64.6 s | 0.03 s |
  | a `Received`, `from a (` 64,000 times | 41.4 s | 0.41 s |
  | one value in 30,000 header fields | 126 s | 0.62 s |
  | a `Cc` of 40,000 periods, a `Content-Type` of 8,000 `(a)` | 158 s | 0.05 s |
  | a `Content-Type` with a million semicolons | over 600 s | 0.12 s |
  | a nested message written out again, its `Cc` 32,000 periods | 233 s | 0.09 s |

  The last five are bounded by the limits below as well: the long headers, the `Received`
  among them, are kept as written, only 1,024 of the 30,000 fields are read, the semicolons are
  not split, and the nested message is written with its headers as stored.

**Limits, each of which adds `truncated` when it applies (SPEC §15):**

- a run of more than 262,144 characters with no white space is skipped whole: a URL of 262,145
  characters gives nothing; one of 262,144 is read as before
- a structured header longer than 8,192 characters, or any header longer than 65,536, is kept
  in `headers{}` as written, not decoded; a structured one gives a single `null` entry in
  `addresses{}`; both are still scanned for candidates. The length is counted as the parser
  hands the value, one character per byte of an 8-bit header, so 40,000 `é` written as UTF-8
  are past the limit — with the same value
- a part's parameters are read only from a header within 8,192 characters: past it, a charset
  is not read (the text is read as undeclared, with no `encoding_fallback`), a name is `null`,
  and a boundary is not read, so the multipart is a leaf, with no `malformed_mime`
- at most 1,024 header fields are read, in the order written: of 1,032, the last eight are not
  read — in a flood of `Received`, the oldest hops, and every field written after them
- `observables[]` lists at most 50,000 places, `links[]` and `resources[]` at most 50,000
  entries each, per response; a link gives two places, its `url` and its `domain`, so 50,001
  links give 50,000 links and the candidates of about 25,000 of them

**Defanged forms (`[D28]`):**

- after a hyphen, a period, a parenthesis, a bracket, a brace or a colon: returned, `defanged`
  — `-one[.]example[.]net`, `(three[.]example[.]net)`, `-hxxp://seven[.]example[.]net/path`,
  `-user[at]eight[.]example[.]net`, `-192[.]0[.]2[.]201`; each gave nothing
- what the old token cut or distorted comes back whole: `hxxp://two[.]example[.]net/p?q=1&r=2`
  was `http://two.example.net/p`, `.../~user` was `http://two.example.net/`, and
  `first.last+tag[at]three[.]example[.]net` was `tag@three.example.net`
- text around a form reads as it would written plainly: `one.example.com(two[.]example[.]net)`
  gives both domains, the first not `defanged`, where it gave nothing; `bücher[.]de` gives
  nothing, as `bücher.de` does, where it gave `cher.de`
- `hxxp`, `hxxps` and `fxp` are re-armed where a URL's scheme stands, in any case and with no
  bracket marker as well: `hxxp://example.net/x` gives `http://example.net/x`, `defanged`, where
  it gave `hxxp://example.net/x`; `fxp[.]example[.]net` is the host `fxp.example.net`, where it
  gave `ftp.example.net`
- a bracket marker is one only as the table writes it: `user[AT]three[.]example[.]net` gives the
  domain `three.example.net`, `defanged`, where it gave nothing
- a defanged range gives both ends: `192[.]0[.]2[.]1...192[.]0[.]2[.]9`; it gave nothing
- a marker for a period at the end is left off with the period: `www.x.co[.]` gives `www.x.co`,
  not `defanged` and with no marker in `value_raw`, where it gave it `defanged`;
  `http://a.example.net/x[.]` gives `http://a.example.net/x`, where it gave `.../x.` `defanged`

**URLs and what is derived from them (`[D30]` to `[D32]`):**

- a comma or a parenthesis stays in a path, query or fragment: `http://example.net/wiki/Foo_(bar)`
  was cut to `.../Foo_(bar`, and `https://example.net/a,b/c?x=1,2#f,g` to `https://example.net/a`
- `[` and `]` end a URL except around an IP-literal host: `http://example.net[1]` gives
  `http://example.net` and its domain, where it gave `http//example.net[1` alone;
  `mailto:a@example.net[1]` gives `a@example.net` and its domain, where it gave
  `a@example.net[1`; `http://[2001:db8::1]/x` keeps its brackets and gives the `ip`
  `2001:db8::1`, where it gave `http//[2001:db8::1`
- in text a host is labels or an IP literal: markup glued to it is left out —
  `**http://a.example.net**` gives `http://a.example.net` and its domain, where it gave
  `http://a.example.net**` and no domain, and the same for `|`, `` ` `` and `~~`; a
  sub-delimiter inside a host makes two URLs — `http://a.example.net;b.example.org/x` gives
  `http://a.example.net` and `b.example.org/x` with their domains, where it gave one URL and the
  domain `a.example.net;b.example.org`; and a damaged host is cut where it is damaged —
  `https://examp!!e.net/a` gives `https://examp` and `e.net/a`, with the domain `e.net`
- a host gives a domain only when it is labels, and a `mailto:` URL gives each recipient that is
  one address: in an attribute, `http://a.example.net;b.example.org/x` and
  `https://exa%6Dple.net/` give no domain, and `mailto:a@example.net,b@example.org` gives
  `a@example.net` and `b@example.org`, where it gave one `email` of both
- recorded costs: a list joined by a comma with no space after a URL with a path is read as one
  path — `http://a.example.net/x,mailto:u@example.net`, `http://a.example.net/x,b@c.example.org`
  and `a.example.net/x,b.example.org` each give one URL, and the address or the second domain is
  no longer returned

**Nested messages written out again (`[D35]`):**

- a nested message whose bytes cannot be located — behind delimiters that end in a bare CR — is
  written with its headers as they were stored, not refolded: its size and hashes move, a long
  line stays whole, and a long part header in it keeps its parameters, so a declared charset
  that cannot be taken now raises `encoding_fallback`
- such a message whose multipart was not segmented and held an 8-bit byte was answered with a
  500 by every release from 0.1.0; it is dissected now, written as stored

**Screenshots, with `SCREENSHOT_URL` set (`[D38]`):**

- each `cid:` reference is pointed at its part whole: with parts `img1` and `img10`,
  `cid:img10` was sent as `cid-2.png0`, the first one's image; `CID:` in capitals is now
  pointed at its part, and `xcid:...` no longer

**Unchanged:**

- an address in an anchor or a resource is read without the grammar and is not re-armed, as
  before: `hxxp://one[.]example[.]net/x` stays as written, with no domain
- a defanged form after a space: identical
- a comma directly before another `scheme://` still ends a URL; `**http://a.example.net/x**`
  still gives `.../x**`, since `*` may end a path; a `data:` URL in text is still cut at its
  comma; an IPv4 address written otherwise in a host, `http://3221225994/`, still gives no `ip`
- a run, a header and a part's parameters within their limits: identical, at 262,144
  characters, at 8,192 and 65,536, and with 800 parameters
- `cid:` written in the visible text of the HTML is rewritten for the renderer too, as before
- every input to which none of the above applies: identical — 2,524 of the 3,719
- the image runs Python 3.13.16, as 0.6.0's does. Its base was rebuilt under its tag while these
  notes were measured — Debian 12.15, OpenSSL 3.0.22 — and this commit, built on both, answered
  every input of these notes identically

Also in this release: Known defects in `CHANGELOG.md` is empty — the defanged form after a hyphen
or a period was the only entry.

Verified against `apache/tika:3.2.3.0` and `gotenberg/gotenberg:8.37.0`.

The release workflow ran the steps added after 0.6.0 for the first time: it fetched the tag as it
was pushed, in place of the checkout's lightweight copy, attached the files with the tag message
as the release's notes, and found the published description identical to that message.

## 0.6.0 — 2026-10-04

`ghcr.io/janwychowaniak/mail-dissect@sha256:bf7b372796dc8c4cbf0a1f7a0bb497e02992d0b3158954d76220ffd0ae23fe62`

Image Id `sha256:a264fcd9d8bd72a720de68acbaf3dae2e1b55b7cbce2fe7a6f134184fb32f87c`, after a pull
and after `docker load` of the release file alike. Python 3.13.16.

A part's name is now read by one rule, which says what the result is (SPEC §6.4, `[D27]`).
Until now the specification said nothing about it, and the code gave the bare name to the parser
of `Content-Disposition`, which rewrote a semicolon and what followed it as a parameter, and
joined two encoded-words only on some patch releases of Python (F21). The name is `filename`, or
`name` where `filename` is not written; the RFC 2231 form wins wherever it stands; the plain
form, once the quoting of its value is undone, loses the white space between two adjacent
encoded-words and nothing else; the form with a charset is read in that charset and no further,
and gives way to the plain one, reported as `encoding_fallback`, when that charset is not taken;
white space at the ends goes, and a period stays.

The `/v1` paths, fields and value sets are unchanged. What moves is `mime_parts[].filename`,
`attachments[].filename` and `.extension`, `artifacts[].filename`, the name of a served
artifact, and `flags`, for a part whose name is written in one of the shapes below. Measured on
the same inputs against 0.5.0 — the saved messages, 3000 generated names and 1000 damaged
messages, every difference classified:

**Changes:**

- an encoded-word followed by a semicolon: the name as written, `résumé;v2.pdf`; it was
  `résumé; v2.pdf`, and with an equals sign after the semicolon the rest came back as a quoted
  parameter, `résumé; x="y.pdf"`, with the extension `pdf"`
- an encoded-word followed by an escaped quotation mark: `résumé".pdf`; it gained a second
  quotation mark at the end, with the extension `pdf"`
- a plain form and an RFC 2231 form of the same name, in either order, in `Content-Disposition`
  or in `Content-Type`: the RFC 2231 form; it was the plain one
- an RFC 2231 form whose charset cannot be looked up, or does not decode what it declares,
  beside a plain one: the plain one, as before, and now with `encoding_fallback`
- a plain form beside a readable RFC 2231 form, where the plain one held an encoded-word that
  did not read cleanly: on a part, `encoding_fallback` is no longer raised, because nothing
  reads the plain form there any more; where the header is the message's own, `headers{}` still
  reads it and the flag stays, as before
- a name declared with a charset whose text looks like an encoded-word: that text; it was
  decoded a second time
- white space at either end of the name, also when an encoded-word put it there: removed, as it
  already was when it stood outside one; a space an encoded-word decodes to inside the name stays
- the extension of a name that begins with a period: none — `.profile` had `profile`; and the
  extension comes from the last path component, so `dir.d/file` has none, where it had `d/file`
- `artifacts[].filename` and the served name follow the name, through the same sanitising as
  before

**Unchanged:**

- two or more adjacent encoded-words in a name, separated by a space, several, a tab, a fold or
  nothing: joined, as on every image published before this one, all of which run Python
  3.13.15 — now by a rule that does not depend on the interpreter; on 3.13.12 the old code kept
  the white space between them
- a name with no encoded-word, in one form: identical
- a name in the RFC 2231 form alone: identical, but for the extension of a name that begins
  with a period or holds a path separator
- a semicolon, an equals sign, a parenthesis, a comma or a quotation mark with no encoded-word
  before it, or inside an encoded-word: identical
- a period at either end of a name: kept in `filename`, as before, and `archive.exe.` still has
  no extension
- every part with no name in these shapes, and everything outside the name, its extension, the
  artifact name and `flags`: identical across the 4040 inputs
- the image's Python moves from 3.13.15 to 3.13.16, as its base is rebuilt under its tag: the
  same commit built on both answered the 4040 inputs identically

Also in this release: each release on GitHub carries the published image as
`mail-dissect-0.6.0.tar.gz`, saved by its full tag, with a `sha256sum` file beside it; the image
Id to compare after `docker load` is recorded above, beside the digest.

Verified against `apache/tika:3.2.3.0` and `gotenberg/gotenberg:8.37.0`.

The release page on GitHub was first published with the message of the commit the tag points at
as its description, not with these notes: the release workflow read a lightweight copy of the
tag. The description was replaced with the tag message the same day; the tag, the image and the
release files were not touched, and the workflow now fetches the tag itself and checks the
published description against it.

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
