"""Probe for the renderer's input: what pointing `cid:` references at their assets costs (F29).

Run, from the repository root:

    uv run python docs/research/probes/render.py

or inside an image with the source on `PYTHONPATH`, as `response.py` says. F29 in ../NOTES.md is
what it prints. The rewrite until 0.7.0 is kept here as `replace_per_part`, the definition of
what it did, and is compared with `_point_at_assets` on the same HTML: a reference to each of
the parts at the start of a long text, which is the shape whose cost is the HTML's length times
the number of parts, and references end to end, which is the most the one pass has to rewrite.
Each is timed best of two. Nothing is sent anywhere.
"""

from __future__ import annotations

import sys
import time
from collections.abc import Callable

from mail_dissect.dissect import _point_at_assets


def replace_per_part(html: str, names: dict[str, str]) -> str:
    """The rewrite until 0.7.0: one replace over the whole HTML for each part."""
    for content_id, name in names.items():
        html = html.replace(f"cid:{content_id}", name)
    return html


def timed(rewrite: Callable[[str, dict[str, str]], str], html: str, names: dict[str, str]) -> float:
    best = float("inf")
    for _ in range(2):
        started = time.perf_counter()
        rewrite(html, names)
        best = min(best, time.perf_counter() - started)
    return best


def main() -> int:
    print(f"python {sys.version.split()[0]}")
    parts = 500
    names = {f"img{i}@example.net": f"cid-{i}.png" for i in range(parts)}
    references = "".join(f'<img src="cid:img{i}@example.net">' for i in range(parts))
    filler = "<p>" + "Dear customer, your order has shipped. " * 50 + "</p>\n"
    for megabytes in (10, 20, 45):
        size = megabytes * 1_000_000
        shapes = {
            "references, then text": references + filler * (size // len(filler)),
            "references end to end": (references * (size // len(references) + 1))[:size],
        }
        for shape, html in shapes.items():
            same = replace_per_part(html, names) == _point_at_assets(html, names)
            print(
                f"  {megabytes} MB, {parts} parts, {shape:22}: per part "
                f"{timed(replace_per_part, html, names):.2f}s  one pass "
                f"{timed(_point_at_assets, html, names):.2f}s  same result {same}"
            )
    # The defect, beside the cost: a Content-ID that is the start of another.
    html, names = '<img src="cid:img10"><img src="cid:img1">', {"img1": "a.png", "img10": "b.png"}
    print(f"  {html!r}: per part {replace_per_part(html, names)!r}")
    print(f"  {' ' * len(repr(html))}  one pass {_point_at_assets(html, names)!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
