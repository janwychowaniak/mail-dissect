"""Response models. Every closed value set of SPEC §5.1 is a `Literal` here.

Widening one of these is a `/v2` change, not an edit: a test asserts that each set still
matches the table in `docs/SPEC.md`.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

ObservableType = Literal["url", "domain", "ip", "email", "hash", "filename"]
ObservableSubtype = Literal["ipv4", "ipv6", "md5", "sha1", "sha256", "sha512"]
SourceKind = Literal["body_text", "body_html", "header", "attachment"]
ArtifactKind = Literal[
    "eml",
    "headers",
    "body_text",
    "body_html",
    "body_text_from_html",
    "attachment",
    "attachment_text",
    "screenshot",
]
ToolState = Literal["ok", "down", "timeout", "skipped", "disabled"]
Flag = Literal[
    "truncated",
    "malformed_mime",
    "encoding_fallback",
    "attachment_unreadable",
    "artifact_store_failed",
]
ResourceElement = Literal["img", "iframe", "link", "style", "other"]


class SourceHashes(BaseModel):
    size: int
    md5: str
    sha1: str
    sha256: str


class AddressOut(BaseModel):
    display_name: str | None = None
    address: str | None = None
    local_part: str | None = None
    domain: str | None = None


class AuthResultOut(BaseModel):
    method: str
    result: str
    params: dict[str, str] = {}


class ReceivedOut(BaseModel):
    """One `Received` hop.

    `with` and `for` are Python keywords and contract field names at the same time, so they
    are aliased on serialisation, and the response is dumped with `by_alias=True`. Overriding
    `model_dump` here instead is silently skipped whenever a parent model dumps this one.
    """

    from_host: str | None = None
    from_ip: str | None = None
    by_host: str | None = None
    with_: str | None = Field(default=None, serialization_alias="with")
    id: str | None = None
    for_: str | None = Field(default=None, serialization_alias="for")
    timestamp: str | None = None

    model_config = {"populate_by_name": True}


class BodyOut(BaseModel):
    text: str | None = None
    html: str | None = None
    text_from_html: str | None = None
    text_artifact_id: str | None = None
    html_artifact_id: str | None = None
    text_from_html_artifact_id: str | None = None
    text_part_index: int | None = None
    html_part_index: int | None = None


class MimePartOut(BaseModel):
    content_type: str
    disposition: str | None = None
    filename: str | None = None
    content_id: str | None = None
    size: int
    charset_declared: str | None = None
    charset_used: str | None = None
    transfer_encoding: str | None = None


class UrlFieldsOut(BaseModel):
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
    rewritten_from: str | None = None
    unwrap_failed: bool = False
    cid_part: int | None = None


class LinkOut(UrlFieldsOut):
    text: str | None = None


class ResourceOut(UrlFieldsOut):
    element: ResourceElement


class ObservableSourceOut(BaseModel):
    kind: SourceKind
    header_name: str | None = None
    header_index: int | None = None
    part_index: int | None = None


class ObservableOut(BaseModel):
    value: str
    value_raw: str
    type: ObservableType
    subtype: ObservableSubtype | None = None
    defanged: bool = False
    ambiguous: bool = False
    occurrences: int = 1
    sources: list[ObservableSourceOut] = []


class AttachmentOut(BaseModel):
    part_index: int
    artifact_id: str | None = None
    text_artifact_id: str | None = None
    filename: str | None = None
    extension: str | None = None
    disposition: str | None = None
    content_id: str | None = None
    declared_mime: str
    detected_mime: str | None = None
    size: int
    md5: str | None = None
    sha1: str | None = None
    sha256: str | None = None


class MessageOut(BaseModel):
    index: int
    depth: int
    headers: dict[str, list[str]] = {}
    addresses: dict[str, list[AddressOut]] = {}
    auth: list[AuthResultOut] = []
    received: list[ReceivedOut] = []
    body: BodyOut = BodyOut()
    mime_parts: list[MimePartOut] = []
    links: list[LinkOut] = []
    resources: list[ResourceOut] = []
    observables: list[ObservableOut] = []
    attachments: list[AttachmentOut] = []


class ArtifactOut(BaseModel):
    artifact_id: str
    message_index: int
    part_index: int | None = None
    kind: ArtifactKind
    filename: str
    mime: str
    size: int
    sha256: str


class ToolsOut(BaseModel):
    tika: ToolState = "disabled"
    renderer: ToolState = "disabled"


class DissectResponse(BaseModel):
    ok: bool = True
    dissect_id: str
    source: SourceHashes
    messages: list[MessageOut] = []
    artifacts: list[ArtifactOut] = []
    tools: ToolsOut = ToolsOut()
    flags: list[Flag] = []


class RegistryVersionsOut(BaseModel):
    public_suffix_list: str
    file_extensions: str


class HealthOut(BaseModel):
    ok: bool
    version: str
    uptime_seconds: int
    tools: ToolsOut
    tools_checked_age_seconds: int | None
    registries: RegistryVersionsOut
    # What this deployment added to the extension registry [D22]. Reported because it
    # changes what the same string is recognised as, so it belongs with the versions.
    extra_file_extensions: list[str]


def substituted(material: str, result: str) -> bool:
    """Whether `result` has a U+FFFD that the sender did not write.

    A U+FFFD the sender did write arrives either as the character itself or, from a raw 8-bit
    header, as its three UTF-8 bytes escaped to surrogates; both are counted as written.
    """
    written = material.count("\ufffd") + material.count("\udcef\udcbf\udcbd")
    return result.count("\ufffd") > written


def scrub_surrogates(value: str) -> tuple[str, bool]:
    """Make a string serialisable, and say whether that lost anything (F5, F17, [D20]).

    One 8-bit byte in a header can produce a lone surrogate, which raises inside the JSON
    encoder on Starlette's path and would turn five bytes of input into a 500, so scrubbing is
    mandatory. The escaped bytes are read back as UTF-8, as the header registry reads the same
    bytes: where they decode, the result is what the sender wrote and there is nothing to
    report; where they do not, U+FFFD stands in and the caller raises `encoding_fallback`.
    """
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        pass
    else:
        return value, False
    try:
        cleaned = value.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
    except UnicodeEncodeError:
        # A surrogate that did not come from a byte: there is nothing to read back.
        return value.encode("utf-8", "replace").decode("utf-8"), True
    return cleaned, substituted(value, cleaned)
