# Changelog

The release notes are the annotated tag messages; this file carries the same notes where they
can be read without git, together with the image digest each version was published under, and
corrections to them.

**A tag is never pushed again, not even to fix its message.** Pushing it runs the release again
and can publish the same version under a different digest, which breaks the one property a
pinned deployment stands on. A wrong line in a tag message is corrected here instead, as an
erratum that says what the tag claims and what is true.

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
