# Fuzzer findings, kept as fixtures

Every input that toppled a dissection or ran past its time limit lives here as bytes, and is
replayed on every run `[D18]`. A seed number in a log is not a regression test: the generator
will draw something else next time, and the case that actually broke the parser is gone.

Externally reported defects arrive the same way — a minimal repro becomes a file here, and the
issue is closed by the file rather than by the discussion.

Name them `<date>-<what-broke>.eml`. The directory being empty means the fuzzer has not found
anything yet, not that nobody looked.
