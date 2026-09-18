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

## Source of truth

`docs/SPEC.md` is the specification. Decisions are numbered `[D#]` there and cited from code
comments and test docstrings. Measured standard-library behaviour lives in
`docs/research/NOTES.md` as `F#`, produced by `docs/research/probes/`. Where the notes and the
spec disagree, the spec wins — the notes record what the world does, the spec records what we
decided. `docs/spec-coverage.md` maps every requirement and acceptance case to its section and
its test; a row without a test is a promise nobody checks.

Defects are reported against `docs/SPEC.md` — its contract and its decision numbers.

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

The Dockerfile must stay buildable with the classic builder — no `RUN --mount`, no heredocs, no
`COPY --link`, no `FROM --platform=` — and CI enforces it with `DOCKER_BUILDKIT=0`.

**Every assertion must be able to fail** `[D17]`. When writing an acceptance test, break the
behaviour it describes and confirm the test goes red; a test that passes against a broken
implementation is worse than no test, because it is counted as coverage.

**One rule, because the forms keep changing.** Every failure of this discipline so far has
been the same thing wearing a different coat: **the test was green for a reason that has
nothing to do with the behaviour it describes.** Five forms have turned up so far, in tests and
in measurements alike, and the sixth will not look like any of them — which is why the rule is
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
- **[D12]** the `eml` artifact carries original bytes; never reassemble a message to produce it
  or its hashes (F1).
- **[D13]** part and nesting limits are established before the tree is built; a limit checked
  afterwards protects against the result, not against the work.
- **[D9]** the observables collector is append-only and scans headers → text → HTML → document
  texts, so the deterministic core of the list does not move when a tool is absent.
- **[D15]** HTML is parsed with the standard library; do not reach for `lxml` for "robustness".
- **[D20]** scrubbing an unserialisable string is reported as `encoding_fallback`, never silent.
