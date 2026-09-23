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
comments and test docstrings. Measured standard-library behaviour lives in
`docs/research/NOTES.md` as `F#`, produced by `docs/research/probes/`. Where the notes and the
spec disagree, the spec wins — the notes record what the world does, the spec records what we
decided. `docs/spec-coverage.md` maps every requirement and acceptance case to its section and
its test; a row without a test is a promise nobody checks.

Defects are reported against `docs/SPEC.md` — its contract and its decision numbers.

## Defect intake

A report arrives as three things, and each has somewhere to land:

- a **minimal synthetic repro** — the structure reproduced, never anyone's content;
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
```

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
nothing to do with the behaviour it describes.** Six forms have turned up so far, in tests and
in measurements alike, and the seventh will not look like any of them — which is why the rule is
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
  on the one next to it.

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
  Two files went out unformatted behind a gate that reported success.
- **`docker run -v "$PWD/file.py:/app.py"`** silently creates a **directory** when the source
  file does not exist, and the container then fails for a reason that looks unrelated.
- **`gh run watch <id>` with its output discarded** returned at once while the runs were still
  queued, and the loop around it reported CI as finished. Poll the run's `status` until it is
  `completed`, and read the conclusion from that.
- **`echo "$body"` in zsh** interprets backslash escapes, so the `\n` inside a JSON string
  becomes a newline and a valid response fails to parse — which reads as the service's fault.
  Write the body to a file (`curl -o`) and parse the file.

**Two fixture traps that will come back:**

- **A byte-fidelity fixture must be deliberately non-canonical** — a refolded header, a
  `From:` with no space after the colon, LF instead of CRLF. A canonical message survives a
  rebuild unchanged (F1), so a canonical fixture proves only that two equal strings are
  equal, and it passes against an implementation that reassembles rather than reads.
- **A timing assertion must be far from both paths' real cost.** `elapsed < 2.0` could not
  tell a pre-parse cut from a full parse of 20 000 parts; at 100 000 parts the two are ~70x
  apart and the same assertion means something.

**Every fuzzer finding becomes a permanent test** with the offending bytes saved as a fixture
`[D18]` — never a seed number in a log.

## Release

Tags are `v*` and must equal `pyproject.version`; CI hard-fails otherwise. The release workflow
publishes `ghcr.io/janwychowaniak/mail-dissect:<version>` and `:latest`. `latest` is not a
contract — the version tag is.

Secret scanning runs in four layers (`.githooks/` plus `.github/workflows/gitleaks.yml`);
activate the hooks once per clone with `git config core.hooksPath .githooks`.

## Key decisions

The full record is `docs/SPEC.md` §22. The ones most likely to be "improved" by accident:

- **[D11]** the MIME tree comes from `policy.compat32`, not `policy.default` — the latter costs
  ~10× per part and would blow the dissection budget on a large message (F3).
- **`COMPAT32_TEXT`**, not stock `compat32`, is the policy every parser uses. The stock one
  hands a header value with an 8-bit byte out as an `email.header.Header`, not a string, and
  "simplifying" the subclass away brings back a 500 on one byte in any header (F17).
- **[D12]** the `eml` artifact carries original bytes; never reassemble a message to produce it
  or its hashes (F1).
- **[D13]** part and nesting limits are established before the tree is built; a limit checked
  afterwards protects against the result, not against the work.
- **[D9]** the observables collector is append-only and scans headers → text → HTML → document
  texts, so the deterministic core of the list does not move when a tool is absent.
- **[D15]** HTML is parsed with the standard library; do not reach for `lxml` for "robustness".
- **[D20]** scrubbing an unserialisable string is reported as `encoding_fallback`, never silent.
- **[D21]** only the ICANN section of the public suffix list is loaded; adding the PRIVATE
  section looks like completeness and silently stops `github.io` and `blogspot.com` from being
  domains at all.
- **[D23]** `malformed_mime` marks what failed to parse, never what merely looks unusual.
  Raising it on a binary body looks like diligence and makes the flag mean nothing.
