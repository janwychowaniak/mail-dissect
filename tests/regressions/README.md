# Fuzzer findings, kept as fixtures

Every input that toppled a dissection or ran past its time limit lives here as bytes, and is
replayed on every run `[D18]`. A seed number in a log is not a regression test: the generator
will draw something else next time, and the case that actually broke the parser is gone.

Externally reported defects arrive the same way — a minimal repro becomes a file here, and the
issue is closed by the file rather than by the discussion.

A defect that is known and not fixed yet has its saved message here as well. That one is not
closed by the file: `tests/test_known_defects.py` states what the contract asks for as an
expected failure in strict mode, next to a control that passes, and `CHANGELOG.md` lists it under
Known defects until the fix removes both.

Name them `<date>-<what-broke>.eml`. The directory being empty means the fuzzer has not found
anything yet, not that nobody looked.
