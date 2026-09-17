"""The two registry snapshots that ship inside the image (SPEC §12).

Neither is ever fetched at runtime: the service has no route out, and a data update is not a
reason to break that. Updating a registry is a new image release, produced by
`scripts/fetch_registries.py`, which also records the provenance this module verifies.

Recognition depends on these files, so their versions are exposed in `/v1/health` — a new
public suffix changes the classification of the same string.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent / "data"

MAX_HOST_LENGTH = 253  # RFC 1035 §2.3.4

_ICANN_BEGIN = "// ===BEGIN ICANN DOMAINS==="
_ICANN_END = "// ===END ICANN DOMAINS==="


class RegistryError(RuntimeError):
    """A registry file is missing, corrupted, or not the one that was shipped."""


@dataclass(frozen=True, slots=True)
class Versions:
    public_suffix_list: str
    file_extensions: str


class Registries:
    """Loaded registries: public suffixes and known file extensions."""

    __slots__ = ("_exceptions", "_extensions", "_extra", "_rules", "_versions", "_wildcards")

    def __init__(
        self,
        rules: frozenset[str],
        wildcards: frozenset[str],
        exceptions: frozenset[str],
        extensions: frozenset[str],
        versions: Versions,
        extra: tuple[str, ...] = (),
    ) -> None:
        self._rules = rules
        self._wildcards = wildcards
        self._exceptions = exceptions
        self._extensions = extensions
        self._versions = versions
        self._extra = extra

    @classmethod
    def load(
        cls,
        data_dir: Path | None = None,
        extra_extensions: Sequence[str] = (),
    ) -> Registries:
        """Read, verify and parse both snapshots. Raises at startup rather than later.

        `extra_extensions` is the deployment's additive supplement [D22]; it never removes
        anything, and it is folded into the reported version because it changes what the
        same string is recognised as.
        """
        directory = data_dir or DATA_DIR
        manifest_path = directory / "registries.json"
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise RegistryError(f"cannot read {manifest_path}: {exc}") from exc

        psl_bytes = cls._read_verified(directory, manifest, "public_suffix_list")
        mime_bytes = cls._read_verified(directory, manifest, "file_extensions")

        rules, wildcards, exceptions = _parse_public_suffix_list(psl_bytes)
        extra = frozenset(item.lstrip(".").lower() for item in extra_extensions)
        extensions = _parse_extensions(mime_bytes) | extra
        versions = Versions(
            public_suffix_list=manifest["public_suffix_list"]["version"],
            file_extensions=_extensions_version(manifest["file_extensions"]["version"], extra),
        )
        return cls(rules, wildcards, exceptions, extensions, versions, tuple(sorted(extra)))

    @staticmethod
    def _read_verified(directory: Path, manifest: dict[str, dict[str, str]], key: str) -> bytes:
        entry = manifest[key]
        path = directory / entry["file"]
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise RegistryError(f"cannot read registry {key} at {path}: {exc}") from exc
        actual = hashlib.sha256(data).hexdigest()
        # The digest is part of the version string reported in /v1/health, so a file that
        # does not match it would make that report a lie.
        if actual != entry["sha256"]:
            raise RegistryError(
                f"registry {key} does not match its manifest digest: "
                f"expected {entry['sha256'][:12]}…, found {actual[:12]}…"
            )
        return data

    @property
    def versions(self) -> Versions:
        return self._versions

    @property
    def extension_count(self) -> int:
        return len(self._extensions)

    @property
    def extra_extensions(self) -> tuple[str, ...]:
        """What the deployment added [D22] — reported, because it changes recognition."""
        return self._extra

    def is_known_extension(self, extension: str) -> bool:
        """Is this a file extension the registry knows? Used for the `filename` grammar."""
        return extension.lower().lstrip(".") in self._extensions

    def public_suffix(self, host: str) -> str | None:
        """The public suffix of `host`, or None when it ends in nothing the registry knows.

        The algorithm is the published one (exact rules, `*` wildcards, `!` exceptions) with
        one deliberate omission: the default "if no rule matches, the prevailing rule is `*`"
        is NOT applied. That fallback exists for deriving a registrable domain from a name
        already known to be one; here it would make every dotted token a domain and
        `wersja.1.2` a candidate, which SPEC §11.2 forbids.
        """
        # A name longer than this is not a host, and treating it as one is not merely
        # wrong but expensive: the search below walks every suffix position, so an
        # unbounded "host" of half a million labels costs quadratic time (RFC 1035 §2.3.4).
        if not host or host.startswith(".") or ".." in host or len(host) > MAX_HOST_LENGTH:
            return None
        labels = host.lower().rstrip(".").split(".")
        count = len(labels)
        best = 0
        for i in range(count):
            candidate = ".".join(labels[i:])
            if candidate in self._exceptions:
                # An exception rule wins outright and gives up its leftmost label.
                remainder = labels[i + 1 :]
                return ".".join(remainder) if remainder else None
            matched = candidate in self._rules
            if not matched and i + 1 < count:
                matched = f"*.{'.'.join(labels[i + 1 :])}" in self._wildcards
            if matched:
                best = max(best, count - i)
        if best == 0:
            return None
        return ".".join(labels[count - best :])


def _parse_public_suffix_list(data: bytes) -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    """Parse the ICANN section only [D21] — the section in use changes recognition."""
    text = data.decode("utf-8")
    start = text.find(_ICANN_BEGIN)
    end = text.find(_ICANN_END)
    if start == -1 or end == -1 or end < start:
        raise RegistryError("public suffix list has no usable ICANN section")
    rules: set[str] = set()
    wildcards: set[str] = set()
    exceptions: set[str] = set()
    for raw_line in text[start:end].splitlines():
        line = raw_line.strip()
        if not line or line.startswith("//"):
            continue
        if line.startswith("!"):
            exceptions.add(line[1:].lower())
        elif line.startswith("*."):
            wildcards.add(line.lower())
        else:
            rules.add(line.lower())
    if not rules:
        raise RegistryError("public suffix list ICANN section parsed to no rules")
    return frozenset(rules), frozenset(wildcards), frozenset(exceptions)


def _extensions_version(base: str, extra: frozenset[str]) -> str:
    """Fold the supplement into the version string [D22].

    Determinism is promised for "the same registry versions" (SPEC §17). A deployment that
    adds extensions recognises the same string differently, so two deployments must not be
    able to report the same version while disagreeing about `payload.scr`.
    """
    if not extra:
        return base
    digest = hashlib.sha256(",".join(sorted(extra)).encode("utf-8")).hexdigest()[:8]
    return f"{base}+extra{len(extra)}/{digest}"


def _parse_extensions(data: bytes) -> frozenset[str]:
    """Derive the extension set from mime-db; the media types themselves are not used."""
    database = json.loads(data.decode("utf-8"))
    extensions = {
        extension.lower()
        for entry in database.values()
        for extension in entry.get("extensions", ())
    }
    if not extensions:
        raise RegistryError("extension registry parsed to no extensions")
    return frozenset(extensions)
