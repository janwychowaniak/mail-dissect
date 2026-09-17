"""Splitting an address into the fields the contract promises (SPEC §9.1).

Every address is decomposed — the same move as with headers. It costs one call to a URL
parser and saves it from every consumer, and `userinfo` in particular is the field nobody
should have to dig out by hand: `https://bank.example@zly.host/` is a host of `zly.host`.

Nothing is filtered by scheme. `mailto:`, `tel:`, `cid:`, `data:` and relative addresses are
all facts about the content, and a relative address in a mail message is a useless fact, but
still a fact.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

import idna


@dataclass(frozen=True, slots=True)
class UrlParts:
    href: str
    scheme: str | None = None
    host: str | None = None
    port: int | None = None
    userinfo: str | None = None
    path: str | None = None
    query: str | None = None
    fragment: str | None = None
    host_idn: str | None = None
    host_punycode: str | None = None


def split(href: str) -> UrlParts:
    """Decompose an address. Never raises: hostile input is the normal input here."""
    try:
        parts = urlsplit(href)
    except ValueError:
        return UrlParts(href=href)

    scheme = parts.scheme.lower() or None
    host = parts.hostname or None
    try:
        port = parts.port
    except ValueError:
        # A port that is not a number is not a reason to lose the rest of the address.
        port = None

    userinfo = None
    if parts.netloc and "@" in parts.netloc:
        userinfo = parts.netloc.rsplit("@", 1)[0] or None

    opaque = None
    if scheme and not parts.netloc:
        # mailto:, cid:, tel:, data: - the part after the scheme is opaque, and `urlsplit`
        # leaves it in `path`, which is where the contract expects it.
        opaque = parts.path or None

    canonical, unicode_form = canonical_host(host) if host else (None, None)
    return UrlParts(
        href=href,
        scheme=scheme,
        host=canonical,
        port=port,
        userinfo=userinfo,
        path=(opaque if opaque is not None else parts.path) or None,
        query=parts.query or None,
        fragment=parts.fragment or None,
        host_idn=unicode_form,
        host_punycode=canonical if canonical and canonical.isascii() else None,
    )


def canonical_host(host: str) -> tuple[str, str | None]:
    """`(punycode-or-lowercased host, unicode form)`; best effort, never an exception.

    `idna` refuses hosts that mail is nevertheless full of — an underscore, a leading hyphen,
    an over-long label (F12). Refusing to report such a host would hide a fact about the
    message, so the fallback is the lowercased original.
    """
    lowered = host.lower().rstrip(".")
    if lowered.isascii():
        try:
            unicode_form = idna.decode(lowered)
        except (idna.IDNAError, UnicodeError, ValueError):
            unicode_form = None
        return lowered, unicode_form if unicode_form != lowered else None
    try:
        encoded = idna.encode(lowered, uts46=True, transitional=False).decode("ascii")
    except (idna.IDNAError, UnicodeError, ValueError):
        return lowered, lowered
    return encoded, lowered
