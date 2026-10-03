# CLAUDE.md — mail-dissect

## Hard constraints (never violate)

- **No judgement.** No score, verdict, threshold, weight, or list of "risky" anything. If a
  change would make the output depend on who is asking, it does not belong here. See
  `docs/SPEC.md` §2.
- **No outbound traffic** other than `TIKA_URL` and `SCREENSHOT_URL`. No DNS lookups, no
  reputation APIs, no fetching of resources referenced by a message, no runtime download of the
  registries. The default test suite runs offline and CI depends on that.
- **No execution of message content.** Nothing is interpreted, rendered in-process, or expanded.
- **Closed value sets stay closed.** `type`, `subtype`, `sources[].kind`, `artifacts[].kind`,
  `flags`, `tools` — extending any of them is a `/v2` change, not a commit.
- **Never log message content or an `artifact_id`.** `dissect_id` may be logged.
- **`async def` endpoints**; outbound calls go through `httpx.AsyncClient` with
  `trust_env=False`. CPU-bound parsing is offloaded with `asyncio.to_thread`, one message or one
  attachment per unit.
- **Test material is synthetic only.** No third-party mail corpora, ever (`docs/SPEC.md` §18).
- **Somebody else's data never enters this repository** — not a corpus, and not statistics
  derived from one. A measurement taken on a maintainer's own mail arrives here as a
  **property to verify, not as figures to quote**: a reader cannot check them, and they were
  not ours to publish. Re-derive the point from something public instead — the registry
  overlap in F14 replaced a corpus count for exactly this reason, and says the same thing
  better.

## Source of truth

`docs/SPEC.md` is the specification. Decisions are numbered `[D#]` there and cited from code
comments and test docstrings. Measured behaviour — of the standard library, the dependencies,
the tools and, where a decision rests on it, the service's own grammars (F20) — lives in
`docs/research/NOTES.md` as `F#`, each saying how it was measured, most of them by a script in
`docs/research/probes/`. Where the notes and the spec disagree, the
spec wins — the notes record what the world does, the spec records what we decided.
`docs/spec-coverage.md` maps every requirement and acceptance case to its section and its test;
a row without a test is a promise nobody checks.

**An identifier is written down before anything cites it.** `F11` and `F12` were cited from
code for a whole release and existed nowhere else, and `[R1]`/`[R6]` were cited from the spec
and defined nowhere; a number that points at nothing looks like evidence and is worse than
none. Numbers are never reassigned or reused: a finding that turns out wrong is corrected under
its own number, and a gap (there is no F9) stays a gap.

Defects are reported against `docs/SPEC.md` — its contract and its decision numbers.

## Defect intake

A report arrives as three things, and each has somewhere to land:

- a **minimal synthetic repro** — the structure reproduced, never anyone's content. Synthetic
  in its wording too: a name, a subject or a label that carries the reporter's scenario is
  rewritten before the file lands, because a fixture is read by everyone and the structure is
  all it is for;
- a **control** — what the difference is visible on, and what shows the measurement reached
  the code at all rather than failing before it;
- a **reference into the contract** — the `[D#]` or the acceptance case it concerns.

They arrive as **two separate lists**, because they ask two different questions:

- **Defects** ask *does this match `docs/SPEC.md`*. The repro becomes a file in
  `tests/regressions/`, replayed on every run `[D18]`; the fix follows it, and the control
  goes into the assertion or its docstring, because that is what separates "fixed" from
  "stopped reproducing".
- **Surprises** ask *is the contract where we want it*. Nothing is broken, so nothing is
  fixed: the answer is a numbered decision in `docs/SPEC.md`, or a recorded "leaving it,
  because…". The `.com`/`.org` collision is the worked example — the rule stayed, the
  documents started saying what it costs.

Keeping them apart is the point: merged into one list, the second question disappears, and it
is usually the more valuable one.

**A defect that is acknowledged and queued goes on the list**: `Known defects` in
`CHANGELOG.md`, its saved message in `tests/regressions/`, and in `tests/test_known_defects.py`
the contract's expectation marked as an expected failure — strict, and limited to
`AssertionError` — next to a control that passes. An expected failure is satisfied by any
failure, so without the control it is one more assertion that cannot fail. The fix removes the
mark and the entry in the same commit; the strict mark is what makes forgetting that impossible.

## Language

All repository content is **English**: code, comments, docstrings, documentation, commit
messages, PR descriptions. In conversation, mirror the language the maintainer uses (often
Polish); that never changes the English-only rule for repository content.

## Toolchain

Python 3.13, FastAPI, `uv` with a committed `uv.lock`, hatchling, `src/` layout, pydantic v2 and
pydantic-settings, ruff at line length 100. One process, no `--workers`: a configuration error
must crash the container visibly.

## Development

```bash
uv sync --frozen
uv run ruff check . && uv run ruff format --check .
uv run mypy --strict src
uv run pytest -q                        # offline; the socket guard is autouse
uv run pytest -q --cov --cov-fail-under=90   # what CI gates on [D17]
uv run pytest -q -m fuzz                # the long fuzz run, random seed
DOCKER_BUILDKIT=0 docker build -t mail-dissect:dev .
docker run --rm -v "$PWD/tests:/tests:ro" mail-dissect:dev python /tests/pins.py
```

**The image's Python is not the developer's.** `python:3.13-slim-bookworm` is rebuilt under
its tag, so the image carries whatever 3.13.x is current (3.13.15 when the suite ran on
3.13.12), and what `headers{}` and `addresses{}` return is that interpreter's parser at work
`[D24]`. `tests/pins.py` holds the expectations that depend on it — the header registry's map
and the values of the saved messages — and needs nothing the image lacks, so the last line
above runs them on the interpreter that ships. CI runs it in the `container` job and the
release workflow runs it on the image it is about to push.

**The tool contracts are checked against real images, by hand.** `tests/test_live_tools.py`
never runs in CI — it needs two containers — and it exists because the fakes prove our side of
the contract and nothing about theirs. Use the versions and flags `compose.yml` pins, not
looser ones, since these tests are also what would notice an allow-list narrowed too far:

```bash
docker run -d --name md-tika -p 127.0.0.1:9998:9998 apache/tika:3.2.3.0
docker run -d --name md-shot -p 127.0.0.1:3000:3000 gotenberg/gotenberg:8.37.0 \
    gotenberg --chromium-disable-javascript=true --chromium-allow-list='^file:///tmp/.*' \
    --chromium-restart-after=5
MAIL_DISSECT_LIVE_TOOLS=1 uv run pytest tests/test_live_tools.py -q -m live
```

The Dockerfile must stay buildable with the classic builder — no `RUN --mount`, no heredocs, no
`COPY --link`, no `FROM --platform=` — and CI enforces it with `DOCKER_BUILDKIT=0`.

**Every assertion must be able to fail** `[D17]`. When writing an acceptance test, break the
behaviour it describes and confirm the test goes red; a test that passes against a broken
implementation is worse than no test, because it is counted as coverage.

**One rule, because the forms keep changing.** Every failure of this discipline so far has
been the same thing wearing a different coat: **the test was green for a reason that has
nothing to do with the behaviour it describes.** Seven forms have turned up so far, in tests and
in measurements alike, and the eighth will not look like any of them — which is why the rule is
worth more than the list:

- **An assertion that cannot fail.** `assert uptime_seconds >= 0` passed for months of
  nothing while the endpoint read a clock that shared no origin with the one it compared
  against. `assert uptime == 125` after advancing the clock by 125 could not.
- **A mutation that never applied.** A search string that no longer matches the source — a
  comment reworded, a line reformatted — leaves the code untouched and the suite green, which
  is indistinguishable from a test that cannot fail. Mutation scripts must assert the match.
- **A flag asserted in place of the property it describes.** `truncated` is set both by a
  dissection cut short and by one that ran to completion past its budget, so asserting the
  flag proved nothing about the deadline being checked *between* units of work. The assertion
  had to be that the result is genuinely shorter than the material.
- **A measurement with no positive control.** "Zero requests reached the listener" was
  measured once against a listener the container could not reach at all; the zero was true and
  meant nothing. **A positive control is to a measurement what a mutation is to a test** —
  the same apparatus, the same path, with the thing you are looking for deliberately present.
- **A silenced error on the step the experiment depends on.** A preparation step whose failure
  is hidden by `2>/dev/null` and an ignored exit status is the same thing as an assertion that
  cannot fail: a `docker rmi` that quietly failed turned the next step into a no-op, and the
  no-op read as a result (F16). Check between steps that the preparation actually happened.
- **A measurement of the neighbour.** F5 measured what one 8-bit header byte does under
  `policy.default`; the tree is read under `compat32` `[D11]`, where that value is not even a
  string, and one such byte in any header of a message was a 500 for a whole release (F17).
  The measurement was true and the decision built on it was right; neither was about the thing
  that shipped. Measure on the configuration that runs — the policy, the image, the host — not
  on the one next to it. It happened again with F18: F7 measured the header registry on values
  written on one line, and `compat32` hands it folded ones, so every folded address header was
  decomposed into nulls for three releases.
- **A behaviour that holds because a neighbour happens to cover it.** A draft of `[D26]` let
  any hyphen stand before an IPv4 address, and a range written `a-b` still returned neither
  end — not because the rule refused the right end, but because the alternative for a domain
  or a file name had swallowed both. Where that alternative does not reach — after a non-ASCII
  letter, an underscore, a hash — the address after the hyphen came back (F20). The same
  showed under mutation: with the lookbehind for a label character taken out, `v192.0.2.1` was
  still refused, by the neighbour, and only `_192.0.2.1` and `é192.0.2.1` went red. A case that
  stays green with its rule removed describes the neighbour. Put the property in the rule
  itself, and keep a case that nothing else covers.

**Mutation is a ritual of every stage, not a gesture.** Before a stage is pushed, pick its
load-bearing behaviours, break each one in the source on purpose, and check that the tests
that describe it go red — and that the break actually landed. The four mutations at the end of
stage 2 found two tests that proved nothing, one of them hiding a behaviour that did not
exist: the pre-parse cut of `[D13]` was written and never wired in, so CI had been confirming
it for a whole stage.

**The same rule in the shell, where nobody looks for it.** Each of these produced a silent
zero that read as a result during this project:

- **`pkill -f <pattern>`** matches full command lines, so it matches the shell that launched
  it and kills itself mid-script. Record the PID at start (`command & echo $!`) and kill that.
- **`cmd | tail -1`** returns `tail`'s exit status, so a failing `cmd` passes an `&&` chain.
  Two files went out unformatted behind a gate that reported success. The same pipe cuts the
  other way: `git push … | grep -E '->…'` died with its filter — `grep` was an alias for
  ugrep, which read `->` as an option — SIGPIPE took the push with it, and the script carried
  on. Redirect to a file and check the outcome (`git status -sb`) instead of filtering it.
- **`docker run -v "$PWD/file.py:/app.py"`** silently creates a **directory** when the source
  file does not exist, and the container then fails for a reason that looks unrelated.
- **`gh run watch <id>` with its output discarded** returned at once while the runs were still
  queued, and the loop around it reported CI as finished. Poll the run's `status` until it is
  `completed`, and read the conclusion from that.
- **`echo "$body"` in zsh** interprets backslash escapes, so the `\n` inside a JSON string
  becomes a newline and a valid response fails to parse — which reads as the service's fault.
  Write the body to a file (`curl -o`) and parse the file.
- **An unquoted `$files` in zsh is one word**, not a list: `grep … $files` got a single
  argument with newlines in it, exited with 2, and a scan for leaked wording read no file at
  all. Feed file lists through `xargs`, and keep a positive control in the scan — a token that
  is certainly there — so an empty result can be told from a scan that never ran.
- **An unquoted glob in zsh aborts the command it is an argument of.** `grep -rn … tests
  --include=*.py` answered `no matches found: --include=*.py` and never ran, so its part of the
  output was empty — and an empty part reads as "nothing mentions it". Quote the pattern
  (`--include='*.py'`), and print the command's own exit status next to what it found.

**Three fixture traps that will come back:**

- **A byte-fidelity fixture must be deliberately non-canonical** — a refolded header, a
  `From:` with no space after the colon, LF instead of CRLF. A canonical message survives a
  rebuild unchanged (F1), so a canonical fixture proves only that two equal strings are
  equal, and it passes against an implementation that reassembles rather than reads.
- **A timing assertion must be far from both paths' real cost.** `elapsed < 2.0` could not
  tell a pre-parse cut from a full parse of 20 000 parts; at 100 000 parts the two are ~70x
  apart and the same assertion means something.
- **Every built fixture writes a header on one line, and a fold between fields is not a fold
  inside one.** The builders never fold, so nothing folded reached the parser for three
  releases (F18). When a folded fixture was finally written, its folds fell between the fields
  of `Received`, and "`received[]` does not change" went into a draft of the release notes on
  its strength — while a fold inside the timestamp did change it. Fold where the value is,
  not only where it is convenient.

**Every fuzzer finding becomes a permanent test** with the offending bytes saved as a fixture
`[D18]` — never a seed number in a log.

## Release

Tags are `v*` and must equal `pyproject.version`; CI hard-fails otherwise. The release workflow
publishes `ghcr.io/janwychowaniak/mail-dissect:<version>` and `:latest`. `latest` is not a
contract — the version tag is.

**What the version number says.** A patch fixes a defect and leaves the contract as it was
(0.1.1). A minor release changes behaviour a consumer can see within `/v1` — which inputs raise
a flag, what a folded header yields, which addresses are candidates — without extending a closed
set (every release from 0.2.0 to 0.5.0); calling that a patch would misdescribe it. Extending a
closed set is `/v2`. `1.0.0` is released when the consumer says so `[D16]`.

**Every release, in this order:** the notes list what changes in behaviour, measured by running
the same inputs on the previous version and on this one rather than derived from the diff — the
inputs chosen for the notes, and a generated corpus with every difference classified, because
chosen inputs only show what was expected (three effects of 0.5.0 that nobody had listed came
out of four thousand generated messages); the tag message is read line by line against those
measurements by someone other than its author before the tag exists, because it cannot be
corrected afterwards (two lines of 0.5.0's were); the tag goes out only after CI is green on the
commit it points at; the release workflow runs the pins on the image it built and pushes nothing
if they fail; the digest is read from two places that must agree — the release workflow's push
and a pull of the tag — and recorded in the README and `CHANGELOG.md`; the image Id likewise,
from the workflow's summary and from loading the release's own archive into an empty store, and
recorded in full `sha256:` form next to the digest; and the published image is run against the
previous one on an input from each line of the notes, the previous version being the control.

**The release files are the published image, by its full tag, and its checksum.** The
workflow's `archive` job pulls what was pushed by its digest, saves it, loads it back into an
empty store and compares the Id (`.github/scripts/archive-image.sh`, F16) before it attaches the
two files. It is the only job with `contents: write`, and it runs after the push: when it fails,
re-run that job alone. Re-running the whole workflow builds and pushes again, and can publish
the same version under another digest — the same reason a tag is never pushed twice.

**An "unchanged" line in the notes is a negative result**, and needs what every negative result
needs: an input on which the change would show if it were there. "`received[]` does not
change" was measured on a hop folded between its fields, where nothing could change, and a
reviewer found the timestamp moving before the tag did.

The release notes are the annotated tag message, mirrored in `CHANGELOG.md` with the digest once
it is published. **A tag is never pushed again, not even to fix its message:** that runs the
release again and can publish the same version under another digest. A wrong line is corrected
in `CHANGELOG.md` as an erratum saying what the tag claims and what is true.

Secret scanning runs in four layers (`.githooks/` plus `.github/workflows/gitleaks.yml`);
activate the hooks once per clone with `git config core.hooksPath .githooks`.

## Key decisions

The full record is `docs/SPEC.md` §22. The ones most likely to be "improved" by accident:

- **[D11]** the MIME tree comes from `policy.compat32`, not `policy.default` — the latter costs
  ~10× per part and would blow the dissection budget on a large message (F3).
- **`COMPAT32_TEXT`**, not stock `compat32`, is the policy every parser uses. The stock one
  hands a header value with an 8-bit byte out as an `email.header.Header`, not a string, and
  "simplifying" the subclass away brings back a 500 on one byte in any header (F17). The same
  fetch is where a value is unfolded (F18): one place, through which the headers of a message,
  of a part and of a nested message all pass. Moving the unfolding "closer to where it is
  needed" — into `header_map`, say — quietly leaves parts and nested messages folded again.
- **[D24]** `headers{}` is the parsed view of a header — unfolded, decoded, a structured header
  as the parser renders it — and the `headers` artifact is the record of how it was written.
  "Restoring the value as written" in `headers{}` looks like fidelity and is a regression; the
  record is already served, byte for byte. Which headers are structured is the interpreter's
  map, pinned by `tests/pins.py` on the image's Python.
- **[D25]** an address entry with no domain is read once more, and taken only when its local
  part is exactly one mailbox with a domain **and no defect**. The defect is the load-bearing
  half: for text after the address, or two addresses inside the quotes, the parser returns a
  mailbox and a defect — one mailbox on 3.13.12, two on 3.13.15 (F19) — so a rule written on the
  count alone takes the first of two addresses and drops the text after one, silently, on one
  interpreter and not the other. An entry that has a domain is never read again, whatever its
  display name looks like.
- **[D12]** the `eml` artifact carries original bytes; never reassemble a message to produce it
  or its hashes (F1).
- **[D13]** part and nesting limits are established before the tree is built; a limit checked
  afterwards protects against the result, not against the work.
- **[D9]** the observables collector is append-only and scans headers → text → HTML → document
  texts, so the deterministic core of the list does not move when a tool is absent.
- **[D26]** a period or a hyphen that touches an IPv4 address is punctuation unless a label
  character continues on its far side: one character, `\w` in any script, the same rule before
  the address and after it. Every part of that is load-bearing and every part looks like
  something to tidy (F20). The old `[\w.-]` class on both sides lost each address that ended a
  sentence. Letting a period through after the address while refusing it before returns the
  left end of `a...b` alone, and half a range reads as a single address. Looking past a run of
  marks instead of at one character keeps `192.0.2.1--static.example.net` whole and returns the
  right end of `a...b` alone. An ASCII-only label character lets `é-192.0.2.1` through, because
  no other alternative swallows that token. And letting a hyphen through whatever follows it
  looks like completeness for `a-b` and cuts `192.0.2.1-static.example.net` into an address and
  the tail of a host name.
- **[D15]** HTML is parsed with the standard library; do not reach for `lxml` for "robustness".
- **[D20]**, SPEC §5.1: `encoding_fallback` fires when, and only when, a declared charset was
  not taken or something was substituted. A scrub that loses nothing — raw UTF-8 in an address
  — is not reported. Flagging every scrub looks like diligence and is the same mistake as `[D23]`:
  a flag that fires where nothing happened teaches its consumer to ignore it.
- **[D21]** only the ICANN section of the public suffix list is loaded; adding the PRIVATE
  section looks like completeness and silently stops `github.io` and `blogspot.com` from being
  domains at all.
- **[D23]** `malformed_mime` marks what failed to parse, never what merely looks unusual.
  Raising it on a binary body looks like diligence and makes the flag mean nothing.
