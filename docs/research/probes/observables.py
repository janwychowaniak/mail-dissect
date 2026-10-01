"""Probe for the indicator grammars: what each of them does with a mark next to a candidate.

Run:  uv run python docs/research/probes/observables.py

F20 in ../NOTES.md is produced by the one function here. Unlike email_stdlib.py this measures
the service itself, so it needs the installed package and nothing else — which is also what a
published image carries, and how the "to 0.4.0" columns of F20 were taken:

    docker run --rm -v "$PWD/docs/research/probes:/probes:ro" --entrypoint python \
        ghcr.io/janwychowaniak/mail-dissect:0.4.0 /probes/observables.py

Read-only and offline: the text goes straight to the collector, no request is made.
"""

from __future__ import annotations

import sys
from importlib.metadata import version

from mail_dissect.observables import Collector, Source
from mail_dissect.registries import Registries

MD5 = "d41d8cd98f00b204e9800998ecf8427e"
E_ACUTE = chr(233)
EN_DASH = chr(0x2013)

# Each grammar's candidate, written where a period or a hyphen touches it.
OTHER_GRAMMARS = [
    ("domain", "host.example.net"),
    ("url", "https://example.net/x"),
    ("email", "user@example.net"),
    ("ipv6", "2001:db8::1"),
    ("hash", MD5),
]
POSITIONS = [
    ("before a period", "x {}. y"),
    ("before a hyphen", "x {}- y"),
    ("after a period", "x .{} y"),
    ("after a hyphen", "x -{} y"),
]

IPV4 = [
    ("alone", "x 192.0.2.1 y"),
    ("before a period", "x 192.0.2.1. y"),
    ("before a period, end of text", "x 192.0.2.1."),
    ("before an ellipsis", "x 192.0.2.1... y"),
    ("before a period and a bracket", "x (192.0.2.1.) y"),
    ("before a hyphen", "x 192.0.2.1- y"),
    ("after a period", "x .192.0.2.1 y"),
    ("after an ellipsis", "x ...192.0.2.1 y"),
    ("after a hyphen", "x -192.0.2.1 y"),
    ("host name tail after a period", "x 192.0.2.1.example.net y"),
    ("word after a period", "x 192.0.2.1.Next y"),
    ("fifth number", "x 192.0.2.1.5 y"),
    ("host name tail after a hyphen", "x 192.0.2.1-static.example.net y"),
    ("suffix after a hyphen", "x 192.0.2.1-rc1 y"),
    ("word and hyphen before", "x word-192.0.2.1 y"),
    ("non-ASCII letter and hyphen before", f"x {E_ACUTE}-192.0.2.1 y"),
    ("underscore and hyphen before", "x under_-192.0.2.1 y"),
    ("hash and hyphen before", f"x {MD5}-192.0.2.1 y"),
    ("word and period before", "x end.192.0.2.1 y"),
    ("non-ASCII letter and period before", f"x {E_ACUTE}.192.0.2.1 y"),
    ("hyphen, line break, host name tail", "x 192.0.2.1-\r\nstatic.example.net y"),
]

RANGES = [
    ("spaces around the hyphen", "x 192.0.2.1 - 192.0.2.9 y"),
    ("en dash", f"x 192.0.2.1{EN_DASH}192.0.2.9 y"),
    ("bare hyphen", "x 192.0.2.1-192.0.2.9 y"),
    ("hyphen, then space", "x 192.0.2.1- 192.0.2.9 y"),
    ("space, then hyphen", "x 192.0.2.1 -192.0.2.9 y"),
    ("three periods", "x 192.0.2.1...192.0.2.9 y"),
    ("two periods", "x 192.0.2.1..192.0.2.9 y"),
    ("with ports", "x 192.0.2.1:80-192.0.2.9:80 y"),
    ("with prefix lengths", "x 192.0.2.1/32-192.0.2.9/32 y"),
    ("after an IPv4-mapped address", "x ::ffff:192.0.2.1-192.0.2.9 y"),
]

# The defanged reading is found by growing a marker outwards to the token that contains it,
# and that token takes the hyphen or the period in front of it along.
DEFANGED = [
    ("domain, after a space", "x host[.]example[.]net y"),
    ("domain, after a hyphen", "x -host[.]example[.]net y"),
    ("domain, after a period", "x .host[.]example[.]net y"),
    ("url, after a hyphen", "x -hxxp://example[.]net/x y"),
    ("email, after a hyphen", "x -user[at]example[.]net y"),
    ("ipv4, after a space", "x 192[.]0[.]2[.]1 y"),
    ("ipv4, after a hyphen", "x -192[.]0[.]2[.]1 y"),
    ("ipv4, before a period", "x 192[.]0[.]2[.]1. y"),
]


def _banner(tag: str, title: str) -> None:
    print(f"\n=== {tag}: {title} ===")


def _found(registries: Registries, text: str) -> str:
    collector = Collector(registries)
    collector.feed_text(text, Source(kind="body_text"))
    found = [
        f"{c.type} {c.value}" + (" (defanged)" if c.defanged else "") for c in collector.finish()
    ]
    return "; ".join(found) if found else "nothing"


def f20_a_mark_next_to_a_candidate() -> None:
    _banner("F20", "a period or a hyphen next to a candidate")
    registries = Registries.load()

    print("the other grammars:")
    for name, candidate in OTHER_GRAMMARS:
        for position, template in POSITIONS:
            text = template.format(candidate)
            print(f"  {name:6s} {position:16s} -> {_found(registries, text)}")

    print("ipv4:")
    for label, text in IPV4:
        print(f"  {label:36s} {text!r:44s} -> {_found(registries, text)}")

    print("a range of ipv4 addresses:")
    for label, text in RANGES:
        print(f"  {label:36s} {text!r:44s} -> {_found(registries, text)}")

    print("a defanged form:")
    for label, text in DEFANGED:
        print(f"  {label:36s} {text!r:44s} -> {_found(registries, text)}")


def main() -> int:
    print(f"python {sys.version.split()[0]}, mail-dissect {version('mail-dissect')}")
    f20_a_mark_next_to_a_candidate()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
