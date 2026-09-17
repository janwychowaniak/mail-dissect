"""Reading hostile HTML in one pass (SPEC §9).

The parser is the standard library's `[D15]`: no C extension reading the one input class we
are guaranteed to receive, and no tree repair that varies with a library version — which
would be a determinism hazard of the same species `[D8]` keeps out of the registries. It
survives every hostile shape tried, sub-second, without raising (F10).

One scan produces one ordered event stream, and `links[]`, `resources[]`, `text_from_html`
and the HTML half of the observables scan are all consumers of it. That is what makes
"document order" implementable and what stops an anchor's address being counted twice.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser

from .models import ResourceElement

# SPEC §9.3 rule 4: the closed set of elements whose boundaries are line breaks.
BLOCK_ELEMENTS = frozenset(
    [
        "address",
        "article",
        "aside",
        "blockquote",
        "center",
        "dd",
        "details",
        "dialog",
        "div",
        "dl",
        "dt",
        "fieldset",
        "figcaption",
        "figure",
        "footer",
        "form",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "header",
        "hr",
        "li",
        "main",
        "nav",
        "ol",
        "p",
        "pre",
        "section",
        "summary",
        "table",
        "tbody",
        "tfoot",
        "thead",
        "tr",
        "ul",
    ]
)
_CELL_ELEMENTS = frozenset({"td", "th"})
_DROPPED_CONTENT = frozenset({"script", "style", "template"})

# SPEC §9.2: a FIXED allowlist of attributes, never an iteration over all of them. Namespace
# declarations are not excluded by value - they are simply never read.
_RESOURCE_ATTRS: dict[str, tuple[ResourceElement, tuple[str, ...]]] = {
    "img": ("img", ("src",)),
    "input": ("img", ("src",)),
    "source": ("img", ("src",)),
    "video": ("other", ("src", "poster")),
    "iframe": ("iframe", ("src",)),
    "frame": ("iframe", ("src",)),
    "link": ("link", ("href",)),
    "object": ("other", ("data",)),
    "embed": ("other", ("src",)),
    "audio": ("other", ("src",)),
    "track": ("other", ("src",)),
    "body": ("other", ("background",)),
    "table": ("other", ("background",)),
    "td": ("other", ("background",)),
    "th": ("other", ("background",)),
}
_SRCSET_ELEMENTS = frozenset({"img", "source"})
_CSS_URL = re.compile(r"""url\(\s*(?:"([^"]*)"|'([^']*)'|([^)\s]*))\s*\)""", re.IGNORECASE)
_CSS_IMPORT = re.compile(r"""@import\s+(?:"([^"]*)"|'([^']*)')""", re.IGNORECASE)
_SPACE_RUN = re.compile(r"[ \t\f\v]+")
_SPACE_AROUND_NEWLINE = re.compile(r" *\n *")
_MANY_NEWLINES = re.compile(r"\n{3,}")
# Every Unicode space separator (category Zs), written as code points: as literals they are
# invisible in the source, and this table is part of a rule two implementations must match.
_UNICODE_SPACES = dict.fromkeys(
    [0x00A0, 0x1680, *range(0x2000, 0x200B), 0x202F, 0x205F, 0x3000], " "
)


@dataclass(frozen=True, slots=True)
class TextEvent:
    text: str


@dataclass(frozen=True, slots=True)
class AnchorEvent:
    href: str
    text: str | None
    element: str


@dataclass(frozen=True, slots=True)
class ResourceEvent:
    href: str
    element: ResourceElement


Event = TextEvent | AnchorEvent | ResourceEvent


@dataclass(slots=True)
class HtmlScan:
    events: list[Event] = field(default_factory=list)
    _text_parts: list[str] = field(default_factory=list)

    def text(self) -> str:
        """The deterministic text rendering of SPEC §9.3."""
        joined = "".join(self._text_parts)
        joined = joined.replace("\r\n", "\n").replace("\r", "\n").translate(_UNICODE_SPACES)
        joined = _SPACE_RUN.sub(" ", joined)
        joined = _SPACE_AROUND_NEWLINE.sub("\n", joined)
        joined = _MANY_NEWLINES.sub("\n\n", joined)
        return joined.strip()


class _Scanner(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.scan = HtmlScan()
        self._dropping: list[str] = []
        self._anchor: tuple[str, str, list[str]] | None = None

    # -- structure ---------------------------------------------------------------------
    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        name = tag.lower()
        values = {key.lower(): (value or "") for key, value in attrs}

        if name in _DROPPED_CONTENT:
            self._dropping.append(name)
            return
        if name in BLOCK_ELEMENTS:
            self._emit_text("\n")
        elif name in _CELL_ELEMENTS:
            self._emit_text(" ")
        elif name == "br":
            self._emit_text("\n")

        self._emit_resources(name, values)

        href = values.get("href", "").strip()
        if name == "a" and href:
            self._close_anchor()
            self._anchor = (href, name, [])
        elif name == "area" and href:
            # A void element: there is no text to wait for.
            self.scan.events.append(AnchorEvent(href=href, text=None, element=name))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag.lower() in _DROPPED_CONTENT and self._dropping:
            self._dropping.pop()

    def handle_endtag(self, tag: str) -> None:
        name = tag.lower()
        if name in _DROPPED_CONTENT:
            if self._dropping:
                self._dropping.pop()
            return
        if name == "a":
            self._close_anchor()
        if name in BLOCK_ELEMENTS:
            self._emit_text("\n")
        elif name in _CELL_ELEMENTS:
            self._emit_text(" ")

    def handle_data(self, data: str) -> None:
        if self._dropping:
            if self._dropping[-1] == "style":
                # The content of a <style> element is where a background image hides.
                self._emit_css(data)
            return
        self._emit_text(data)
        if self._anchor is not None:
            self._anchor[2].append(data)
        self.scan.events.append(TextEvent(text=data))

    # -- helpers -----------------------------------------------------------------------
    def _emit_text(self, text: str) -> None:
        self.scan._text_parts.append(text)

    def _close_anchor(self) -> None:
        if self._anchor is None:
            return
        href, element, chunks = self._anchor
        self._anchor = None
        text = "".join(chunks).strip() or None
        self.scan.events.append(AnchorEvent(href=href, text=text, element=element))

    def _emit_resources(self, name: str, values: dict[str, str]) -> None:
        mapping = _RESOURCE_ATTRS.get(name)
        if mapping:
            element, attributes = mapping
            if name == "input" and values.get("type", "").lower() != "image":
                attributes = ()
            for attribute in attributes:
                href = values.get(attribute, "").strip()
                if href:
                    self.scan.events.append(ResourceEvent(href=href, element=element))
        if name in _SRCSET_ELEMENTS and values.get("srcset"):
            for candidate in values["srcset"].split(","):
                href = candidate.strip().split(" ")[0].strip()
                if href:
                    self.scan.events.append(ResourceEvent(href=href, element="img"))
        if values.get("style"):
            self._emit_css(values["style"])

    def _emit_css(self, css: str) -> None:
        for match in _CSS_URL.finditer(css):
            href = (match.group(1) or match.group(2) or match.group(3) or "").strip()
            if href:
                self.scan.events.append(ResourceEvent(href=href, element="style"))
        for match in _CSS_IMPORT.finditer(css):
            href = (match.group(1) or match.group(2) or "").strip()
            if href:
                self.scan.events.append(ResourceEvent(href=href, element="style"))


def scan_html(html: str) -> HtmlScan:
    """Scan once. Never raises: `html.parser` survives what mail carries (F10)."""
    scanner = _Scanner()
    try:
        scanner.feed(html)
        scanner.close()
    except Exception:
        pass
    scanner._close_anchor()
    return scanner.scan
