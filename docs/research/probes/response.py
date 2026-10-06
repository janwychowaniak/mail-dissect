"""Probe for the response: what serialising it costs by the length of its lists (F28).

Run, from the repository root, on the interpreter and the dependencies the image ships:

    docker run --rm --network none -v "$PWD:/repo:ro" -e PYTHONPATH=/repo/src \\
        --entrypoint python ghcr.io/janwychowaniak/mail-dissect:<version> \\
        /repo/docs/research/probes/response.py

or locally with `uv run python docs/research/probes/response.py`. F28 in ../NOTES.md is what it
prints. A response is built with all three lists at 50,000, the case the limits are set by, and
then with one list of a given length and the others empty; `model_dump` and the JSON render are
each timed, best of two, and the peak memory of the process is read after the first. Nothing is
sent anywhere.
"""

from __future__ import annotations

import gc
import resource
import sys
import time

from fastapi.responses import JSONResponse

from mail_dissect.models import (
    BodyOut,
    DissectResponse,
    LinkOut,
    MessageOut,
    ObservableOut,
    ObservableSourceOut,
    ResourceOut,
    SourceHashes,
    ToolsOut,
)

URL_FIELDS = {
    "scheme": "http",
    "host": "h.example.net",
    "port": None,
    "userinfo": None,
    "path": "/p",
    "query": None,
    "fragment": None,
    "host_idn": None,
    "host_punycode": "h.example.net",
    "rewritten_from": None,
    "unwrap_failed": False,
    "cid_part": None,
}


def response(observables: int = 0, links: int = 0, resources: int = 0) -> DissectResponse:
    """One message whose lists hold that many entries; each observable has one place."""
    source = ObservableSourceOut(kind="body_text", part_index=0)
    message = MessageOut(
        index=0,
        depth=0,
        headers={},
        addresses={},
        auth=[],
        received=[],
        body=BodyOut(),
        mime_parts=[],
        links=[
            LinkOut(href=f"http://h{i}.example.net/p", text=f"link {i}", **URL_FIELDS)
            for i in range(links)
        ],
        resources=[
            ResourceOut(href=f"http://h{i}.example.net/i.png", element="img", **URL_FIELDS)
            for i in range(resources)
        ],
        attachments=[],
        observables=[
            ObservableOut(
                value=f"h{i}.example.net",
                value_raw=f"h{i}.example.net",
                type="domain",
                sources=[source],
            )
            for i in range(observables)
        ],
    )
    return DissectResponse(
        dissect_id="x" * 22,
        source=SourceHashes(size=1, md5="0", sha1="0", sha256="0"),
        messages=[message],
        artifacts=[],
        tools=ToolsOut(tika="disabled", renderer="disabled"),
        flags=[],
    )


def serialised(built: DissectResponse) -> tuple[float, float, int]:
    best = (float("inf"), float("inf"), 0)
    for _ in range(2):
        gc.collect()
        start = time.perf_counter()
        dumped = built.model_dump(by_alias=True)
        dump = time.perf_counter() - start
        start = time.perf_counter()
        body = JSONResponse(content=dumped).body
        render = time.perf_counter() - start
        best = min(best, (dump, render, len(body)))
    return best


def peak() -> float:
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024


def main() -> int:
    print(f"python {sys.version.split()[0]}, peak memory at start {peak():.0f} MB")
    # The case the limits are set by comes first, so the peak it reports is its own.
    count = 50_000
    dump, render, size = serialised(response(observables=count, links=count, resources=count))
    print(
        f"  all three at {count}: model_dump {dump:.2f}s  render {render:.2f}s  "
        f"body {size / 1e6:.1f} MB  peak memory {peak():.0f} MB"
    )
    for kind in ("observables", "links", "resources"):
        for count in (25_000, 50_000, 100_000):
            dump, render, size = serialised(response(**{kind: count}))
            print(
                f"  {kind:11} {count:>7}: model_dump {dump:.2f}s  render {render:.2f}s  "
                f"body {size / 1e6:.1f} MB"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
