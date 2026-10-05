"""Probe for the indicator grammar: what it reads, what a change to it moves, and what it costs.

Run, from the repository root:

    uv run python docs/research/probes/grammar.py layer1 <old> [<new>]
    uv run python docs/research/probes/grammar.py layer2 <old> [<new>]
    uv run python docs/research/probes/grammar.py sweep [<rev>]
    uv run python docs/research/probes/grammar.py defang [<rev>]

F22 in ../NOTES.md is produced here. A revision is anything `git archive` takes; `.`, the
default for <new> and <rev>, is the working tree. Each tree is imported in a process of its
own, which asserts that `mail_dissect` came from the tree it was given, so a comparison can
never quietly be a tree against itself.

- `layer1`: the grammar's readings, old against new, on generated strings: every unit of one
  and two symbols and a seeded sample of longer ones, the shapes the readings depend on today,
  a short prefix followed by a long run for each grammar with structure, and runs of words with
  white space between them. For each string, the spans `_scan` takes and the candidates the
  collector makes from them.
- `layer2`: the full response, old against new, of every message the test suite sends, plus
  the saved messages and the golden samples, with the text extractor and the renderer absent
  and present. The suite is run once on the working tree to record what it sends.
- `sweep`: the cost of a run made of one short unit, doubled until it takes long enough that
  a per-call cost cannot hide the term being looked for. The verdict is read from the last
  doubling, best of two.
- `defang`: the defanged forms of the known defect and of the paths it shares, as read.

Each of `layer1` and `layer2` prints a positive control: the same comparison with one input
changed, which must show as exactly that input.

Read-only and offline: nothing is sent anywhere, and the files written are in a temporary
directory.
"""

from __future__ import annotations

import base64
import hashlib
import itertools
import json
import os
import random
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]

SYMBOLS = [*"a1.-/:@_+=?#%&~!*'\"()[]{}<>,;$^`|", chr(0xE9)]
TOKENS = [
    *("[.]", "(.)", "{.}", "[dot]", "(dot)", "[:]", "[at]", "(at)", "[@]"),
    *("hxxp://", "hxxps://", "fxp://", "http://", "https://", "www.", "mailto:"),
    *("a.b", "1.1", "::", "a@a", "x.co", "ab12", "example.net", "192.0.2.1", "+tag"),
]
WHITE = [" ", "\t", "\n", "\r\n", chr(0xA0), chr(0x2003), chr(0x3000)]

# The readings these strings give today are what a change to the grammar has to keep, or has
# to record as a decision. Each line is one family.
SHAPES = [
    # Where a candidate starts inside a run that an earlier candidate ended in.
    "x:/y'z@a.example.com",
    "http://h.example.com/p'q@r.example.com",
    "::1.a-b@c.example.com",
    "a.b..c@d.example.com",
    # Local parts.
    "first.last+tag@example.net",
    "a+b+c@x.example.org",
    "x first.last+tag[at]three[.]example[.]net y",
    # IPv4 next to a mark [D26].
    "a 192.0.2.1.",
    "192.0.2.1-static.example.net",
    "a-192.0.2.1",
    "192.0.2.1...192.0.2.9",
    f"{chr(0xE9)}-192.0.2.1",
    "_192.0.2.1",
    "v192.0.2.1",
    "192.0.2.1--static.example.net",
    # Defanged forms, after a mark and after a space.
    "-one[.]example[.]net",
    ".one[.]example[.]net",
    "- one[.]example[.]net",
    "-hxxp://two[.]example[.]net/path",
    "-user[at]three[.]example[.]net",
    "-192[.]0[.]2[.]201",
    "x (hxxp://two[.]example[.]net/path) y",
    "x hxxp://two[.]example[.]net/p?q=1&r=2 y",
    "x hxxp://two[.]example[.]net/~user y",
    f"x b{chr(0xFC)}cher[.]de y",
    "x one.example.com(two[.]example[.]net) y",
    "x user[AT]three[.]example[.]net y",
    "x fxp[.]example[.]net y",
    "x x-hxxp://a[.]example[.]net y",
    # URLs: wrapped, and with the characters the URL class decides about.
    "see http://example.net/a/very/long/path/that/wraps/\nonto/the/next/line here",
    "see http://example.net/" + "segment/" * 40 + " here",
    "http://example.net/wiki/Foo_(bar)",
    "http://example.net/?ids=1,2,3",
    "http://example.net/a,b/c",
    "http://example.net[1]",
    "http://example.net/path[2].",
    "http://[2001:db8::1]/x",
    "mailto:a@example.net,b@example.net",
    "mailto:a@example.net[1]",
    "sip:a@example.net",
    "data:text/plain;base64,QUJD",
    "(see http://example.net/x.)",
    "<http://example.net/>,<mailto:a@example.net>",
    "http://example.net/x,mailto:u@example.net",
    "**http://a.example.net**",
    "|www.a.example.net|",
    "http://a.example.net:80;x",
    "www.a.example.net;b.example.org",
    "http://a.example.net;b.example.org/x",
    "http://example.net/x}}}}",
    "http://example.net/x....",
    "http://example.net/x))))",
]

# A short prefix that opens a grammar's structure, then a long run that never completes it.
PREFIXES = ["", "http://", "a@", "www.", "x:", "mailto:", "user+", "a.b..", "::1.", "hxxp://"]
RUN_UNITS = ["a", "a-", "-a", "a.", "a/", "a:", "a=", "a+", "1.", "a[.]", "}", ".", ")", ","]


def layer1_strings(seed: int = 22) -> list[str]:
    rng = random.Random(seed)
    units = SYMBOLS + ["".join(pair) for pair in itertools.product(SYMBOLS, repeat=2)]
    pool = SYMBOLS + TOKENS
    units += ["".join(rng.choice(pool) for _ in range(rng.randint(3, 5))) for _ in range(1500)]
    units = list(dict.fromkeys(units))
    strings: list[str] = []
    for unit in units:
        run = (unit * (60 // len(unit) + 1))[:60]
        strings += [run, f"x {run} y", f"{unit} example.net {unit}"]
    strings += SHAPES
    strings += [prefix + (unit * 1000)[:1000] for prefix in PREFIXES for unit in RUN_UNITS]
    words = ["word", "a", "=?a", "x.example.net", "a.b", "u@example.org", "192.0.2.7", "a-b"]
    for word, white in itertools.product(words, WHITE):
        strings.append((word + white) * 50)
    return strings


SWEEP_UNITS_SEED = 2257


def sweep_units() -> list[str]:
    rng = random.Random(SWEEP_UNITS_SEED)
    units = SYMBOLS + ["".join(pair) for pair in itertools.product(SYMBOLS, repeat=2)]
    pool = SYMBOLS + TOKENS
    units += ["".join(rng.choice(pool) for _ in range(rng.randint(3, 5))) for _ in range(500)]
    return list(dict.fromkeys(units))


# The forms of the known defect, the same forms after a space, and the shapes the defanged
# path shares with them: a token grown over characters a mark stands next to.
DEFANG_CASES = [
    "-one[.]example[.]net",
    "- one[.]example[.]net",
    ".one[.]example[.]net",
    ". one[.]example[.]net",
    "-hxxp://two[.]example[.]net/path",
    "-user[at]three[.]example[.]net",
    "-192[.]0[.]2[.]201",
    "x (hxxp://two[.]example[.]net/path) y",
    "x [one[.]example[.]net] y",
    "x hxxp://two[.]example[.]net/p?q=1&r=2 y",
    "x hxxp://two[.]example[.]net/~user y",
    "x first.last+tag[at]three[.]example[.]net y",
    f"x b{chr(0xFC)}cher[.]de y",
    "x one.example.com(two[.]example[.]net) y",
]


# -- the worker: one tree, one task, in a process of its own --------------------------------
def _task_scan(texts: list[str]) -> list[dict[str, Any]]:
    from mail_dissect import observables
    from mail_dissect.observables import Collector, Source
    from mail_dissect.registries import Registries

    registries = Registries.load()
    source = Source(kind="body_text", part_index=0)
    out = []
    for text in texts:
        collector = Collector(registries)
        collector.feed_text(text, source)
        out.append(
            {
                "spans": [list(item) for item in observables._scan(text)],
                "candidates": [
                    [
                        c.value,
                        c.value_raw,
                        c.type,
                        c.subtype,
                        c.defanged,
                        c.ambiguous,
                        c.occurrences,
                    ]
                    for c in collector.finish()
                ],
            }
        )
    return out


def _task_responses(messages: list[list[str]]) -> dict[str, dict[str, Any]]:
    import httpx
    from conftest import mask_environment
    from fastapi.testclient import TestClient

    from mail_dissect.app import create_app
    from mail_dissect.settings import Settings

    def tools(request: httpx.Request) -> httpx.Response:
        if request.method == "PUT":
            return httpx.Response(200, text="document text with doc.example.net and 192.0.2.7")
        return httpx.Response(
            200, content=b"\x89PNG\r\n\x1a\nimage", headers={"content-type": "image/png"}
        )

    out: dict[str, dict[str, Any]] = {}
    with tempfile.TemporaryDirectory() as store:
        for mode in ("no tools", "tools"):
            overrides: dict[str, Any] = {"artifact_dir": store}
            if mode == "tools":
                overrides |= {
                    "tika_url": "http://tika.invalid/t",
                    "screenshot_url": "http://s.invalid/",
                }
            app = create_app(
                Settings(_env_file=None, **overrides), transport=httpx.MockTransport(tools)
            )
            results: dict[str, Any] = {}
            with TestClient(app) as client:
                for name, encoded in messages:
                    response = client.post(
                        "/v1/dissect",
                        content=base64.b64decode(encoded),
                        headers={"content-type": "message/rfc822"},
                    )
                    results[name] = [response.status_code, mask_environment(response.json())]
            out[mode] = results
    return out


def _task_sweep(payload: dict[str, Any]) -> list[list[Any]]:
    from mail_dissect.observables import Collector, Source
    from mail_dissect.registries import Registries

    registries = Registries.load()
    source = Source(kind="body_text", part_index=0)

    def cost(text: str) -> float:
        best = float("inf")
        for _ in range(2):
            collector = Collector(registries)
            started = time.perf_counter()
            collector.feed_text(text, source)
            best = min(best, time.perf_counter() - started)
        return best

    out = []
    for unit in payload["units"]:
        size, rows = payload["start"], []
        while True:
            text = (unit * (size // len(unit) + 1))[:size]
            rows.append([size, cost(text)])
            done = rows[-1][1] >= payload["enough"] or size >= payload["largest"]
            if done and len(rows) >= 2:
                break
            size *= 2
        out.append([unit, rows])
    return out


TASKS = {"scan": _task_scan, "responses": _task_responses, "sweep": _task_sweep}


def _worker(src: str, task: str, request: str, response: str) -> None:
    sys.path.insert(0, src)
    sys.path.insert(1, str(ROOT / "tests"))
    import mail_dissect

    assert Path(mail_dissect.__file__).resolve().is_relative_to(Path(src).resolve()), (
        f"imported {mail_dissect.__file__}, not the tree in {src}"
    )
    result = TASKS[task](json.loads(Path(request).read_text()))
    Path(response).write_text(json.dumps(result))
    print(f"  {src}: python {sys.version.split()[0]}", file=sys.stderr)


# -- the parent: trees, runs, comparisons ---------------------------------------------------
def _tree(rev: str, into: Path) -> Path:
    """The `src` directory of a revision; `.` is the working tree."""
    if rev == ".":
        return ROOT / "src"
    target = into / hashlib.sha256(rev.encode()).hexdigest()[:12]
    target.mkdir()
    archive = subprocess.run(
        ["git", "-C", str(ROOT), "archive", rev, "src"], check=True, capture_output=True
    ).stdout
    subprocess.run(["tar", "-x", "-C", str(target)], input=archive, check=True)
    assert (target / "src" / "mail_dissect" / "observables.py").is_file(), f"{rev}: no tree"
    return target / "src"


def _run(src: Path, task: str, payload: object, work: Path) -> Any:
    tag = hashlib.sha256(f"{src}{task}".encode()).hexdigest()[:12]
    request, response = work / f"{tag}-in.json", work / f"{tag}-out.json"
    request.write_text(json.dumps(payload))
    subprocess.run(
        [sys.executable, "-B", __file__, "--worker", str(src), task, str(request), str(response)],
        check=True,
        stdout=subprocess.DEVNULL,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    return json.loads(response.read_text())


def _compare(labels: list[str], old: list[Any], new: list[Any]) -> list[str]:
    assert len(old) == len(new) == len(labels)
    return [label for label, a, b in zip(labels, old, new, strict=True) if a != b]


def layer1(old: str, new: str) -> None:
    strings = layer1_strings()
    control = list(strings)
    control[7] = control[7] + " control.example.net"
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        old_src, new_src = _tree(old, work), _tree(new, work)
        old_out = _run(old_src, "scan", strings, work)
        new_out = _run(new_src, "scan", strings, work)
        control_out = _run(new_src, "scan", control, work)
    labels = [repr(s[:80]) for s in strings]
    differ = _compare(labels, old_out, new_out)
    print(f"layer 1, {old} against {new}: {len(strings)} strings compared, {len(differ)} differ")
    shown = [(text, a, b) for text, a, b in zip(strings, old_out, new_out, strict=True) if a != b]
    for text, a, b in shown[:20]:
        print(f"  {text[:80]!r}\n    old {a}\n    new {b}")
    control_differ = _compare(labels, new_out, control_out)
    print(f"  control, one string changed: {len(control_differ)} differ ({control_differ})")


def _record_suite() -> dict[str, bytes]:
    """Every message the suite sends to `/v1/dissect`, recorded on the working tree."""
    import pytest

    recorded: dict[str, bytes] = {}

    class Recorder:
        def pytest_configure(self, config: object) -> None:
            from mail_dissect import routes

            original = routes.build_response

            async def recording(raw: bytes, *args: Any, **kwargs: Any) -> Any:
                recorded.setdefault(hashlib.sha256(raw).hexdigest()[:16], raw)
                return await original(raw, *args, **kwargs)

            routes.build_response = recording  # type: ignore[assignment]

    sys.path.insert(0, str(ROOT / "tests"))
    status = pytest.main(
        ["-q", "-p", "no:cacheprovider", "-m", "not fuzz and not live", str(ROOT / "tests")],
        plugins=[Recorder()],
    )
    assert status == 0, f"the suite did not pass on the working tree (exit {status})"
    return recorded


def layer2(old: str, new: str) -> None:
    messages = _record_suite()
    from test_determinism import _sample_messages

    for path in sorted((ROOT / "tests" / "regressions").glob("*.eml")):
        messages[f"saved:{path.name}"] = path.read_bytes()
    for name, raw in _sample_messages().items():
        messages[f"golden:{name}"] = raw
    payload = [[name, base64.b64encode(raw).decode()] for name, raw in messages.items()]
    control = [list(item) for item in payload]
    changed = sorted(messages)[3]
    for item in control:
        if item[0] == changed:
            item[1] = base64.b64encode(b"X-Control: c.example.net\r\n" + messages[changed]).decode()
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        old_src, new_src = _tree(old, work), _tree(new, work)
        old_out = _run(old_src, "responses", payload, work)
        new_out = _run(new_src, "responses", payload, work)
        control_out = _run(new_src, "responses", control, work)

    def summary(result: list[Any]) -> str:
        status, body = result
        if status != 200:
            return f"status {status}"
        found = sum(len(message["observables"]) for message in body["messages"])
        return f"flags {body['flags']}, {len(body['messages'])} messages, {found} candidates"

    for label, first, second in (
        (f"{old} against {new}", old_out, new_out),
        (f"control, {changed} changed, against {new}", new_out, control_out),
    ):
        differ = [
            (mode, name)
            for mode in first
            for name in first[mode]
            if first[mode][name] != second[mode][name]
        ]
        total = sum(len(results) for results in first.values())
        print(f"layer 2, {label}: {total} responses compared, {len(differ)} differ")
        for mode, name in differ[:20]:
            size = len(messages[name])
            print(f"  {mode}: {name} ({size} bytes)")
            print(f"    before: {summary(first[mode][name])}")
            print(f"    after:  {summary(second[mode][name])}")
    saved = len(list((ROOT / "tests" / "regressions").glob("*.eml")))
    print(f"  ({len(messages)} messages: the suite's, {saved} saved, the golden samples)")


def sweep(rev: str) -> None:
    units = sweep_units()
    payload = {"units": units, "start": 1_000, "enough": 0.2, "largest": 128_000}
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        rows = _run(_tree(rev, work), "sweep", payload, work)
    flagged = []
    for unit, sizes in rows:
        (_, t_small), (large, t_large) = sizes[-2], sizes[-1]
        ratio = t_large / max(t_small, 1e-9)
        if ratio > 3.0 and t_large > 0.01:
            flagged.append((t_large / large * 1e6, ratio, large, unit))
    worst = max(rows, key=lambda row: row[1][-1][1] / row[1][-1][0])
    print(
        f"sweep of {rev}: {len(units)} units, doubled from 1 000 characters until 0.2 s or 128 000"
    )
    print(f"  {len(flagged)} grow faster than linearly at their last doubling (ratio > 3)")
    for per_char, ratio, size, unit in sorted(flagged, reverse=True)[:25]:
        print(
            f"    {unit!r:10} x{ratio:.1f} at {size:>7} characters, {per_char:.2f} us per character"
        )
    unit, sizes = worst
    size, seconds = sizes[-1]
    print(
        f"  slowest per character at its last size: {unit!r}, "
        f"{seconds / size * 1e6:.2f} us at {size}"
    )


def defang(rev: str) -> None:
    payload = {
        "units": ["a[.]", "a."],
        "start": 50_000,
        "enough": float("inf"),
        "largest": 200_000,
    }
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        src = _tree(rev, work)
        out = _run(src, "scan", DEFANG_CASES, work)
        costs = _run(src, "sweep", payload, work)
    print(f"defanged forms read by {rev}:")
    for text, result in zip(DEFANG_CASES, out, strict=True):
        found = [(c[2], c[0], c[4]) for c in result["candidates"]]
        print(f"  {text!r:48} {found}")
    print("  cost of a run of markers, and of the same run written plainly (the control):")
    for unit, rows in costs:
        cells = "  ".join(f"{size // 1000}k {seconds:.2f}s" for size, seconds in rows)
        print(f"    {unit!r:8} {cells}")


def main() -> int:
    if sys.argv[1:2] == ["--worker"]:
        _worker(*sys.argv[2:6])
        return 0
    command, *revisions = sys.argv[1:]
    print(f"python {sys.version.split()[0]}")
    if command in ("layer1", "layer2"):
        old, new = revisions[0], revisions[1] if len(revisions) > 1 else "."
        (layer1 if command == "layer1" else layer2)(old, new)
    elif command == "sweep":
        sweep(revisions[0] if revisions else ".")
    elif command == "defang":
        defang(revisions[0] if revisions else ".")
    else:
        raise SystemExit(__doc__)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
