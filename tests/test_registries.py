"""The bundled registries: SPEC §12 and [D21]."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from mail_dissect.registries import DATA_DIR, Registries, RegistryError


@pytest.fixture(scope="module")
def registries() -> Registries:
    return Registries.load()


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("example.com", "com"),
        ("a.example.co.uk", "co.uk"),
        ("foo.bar.ck", "bar.ck"),  # the *.ck wildcard rule
        ("www.ck", "ck"),  # the !www.ck exception rule
        ("a.b.mm", "b.mm"),
        # [D21]: with the PRIVATE section loaded these would be public suffixes themselves,
        # and a bare occurrence in a message would yield no candidate at all.
        ("github.io", "io"),
        ("blogspot.com", "com"),
        ("s3.amazonaws.com", "com"),
        # Test 33: grammar alone would call this a domain; the registry is what refuses.
        ("wersja.1.2", None),
        ("localhost", None),
        ("nothing.invalidtld", None),
        ("", None),
    ],
)
def test_public_suffix(registries: Registries, host: str, expected: str | None) -> None:
    assert registries.public_suffix(host) == expected


def test_the_default_star_rule_is_not_applied(registries: Registries) -> None:
    """The published algorithm falls back to `*`; applying it here would make every dotted
    token a domain, which is exactly what test 33 forbids (SPEC §12)."""
    assert registries.public_suffix("anything.zzzznotatld") is None


def test_known_extensions(registries: Registries) -> None:
    for extension in ("pdf", "PDF", ".docx", "zip", "md", "exe"):
        assert registries.is_known_extension(extension), extension
    assert not registries.is_known_extension("zzznotanextension")


def test_versions_name_what_recognition_depends_on(registries: Registries) -> None:
    versions = registries.versions
    assert "+icann/" in versions.public_suffix_list  # the section is an input to recognition
    assert versions.file_extensions.startswith("mime-db@")


def test_a_registry_that_does_not_match_its_manifest_is_refused(tmp_path: Path) -> None:
    """The digest is part of what /v1/health reports; a mismatch would make that a lie."""
    for name in ("registries.json", "public_suffix_list.dat", "mime-db.json"):
        shutil.copy(DATA_DIR / name, tmp_path / name)
    manifest = json.loads((tmp_path / "registries.json").read_text())
    manifest["public_suffix_list"]["sha256"] = "0" * 64
    (tmp_path / "registries.json").write_text(json.dumps(manifest))

    with pytest.raises(RegistryError, match="does not match its manifest digest"):
        Registries.load(tmp_path)
