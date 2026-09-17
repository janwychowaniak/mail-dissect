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
