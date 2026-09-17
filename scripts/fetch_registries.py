"""Fetch the registry snapshots that ship inside the image.

    python3 scripts/fetch_registries.py

This is a BUILD step, never a runtime one: the service has no route out and must not
reach for these files while it is working (SPEC §12). Updating a registry is a new image
release, so this script is run by a maintainer, its output is committed, and the resulting
`registries.json` records exactly what was fetched, when, and under which licence.

Both sources are pinned. `mime-db` is pinned to a version; the public suffix list has no
versioned URL, so the snapshot is identified by the `VERSION:` header the file carries and
by the digest of its content.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import urllib.request
from datetime import date
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "src" / "mail_dissect" / "data"

PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"
MIME_DB_VERSION = "1.54.0"
MIME_DB_URL = f"https://cdn.jsdelivr.net/npm/mime-db@{MIME_DB_VERSION}/db.json"

USER_AGENT = "mail-dissect-registry-fetch/1.0 (+https://github.com/janwychowaniak/mail-dissect)"


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def psl_upstream_version(data: bytes) -> str:
    """The list carries its own release identifier; prefer it over a snapshot date."""
    match = re.search(rb"^// VERSION: (.+)$", data, re.MULTILINE)
    if match is None:
        return date.today().isoformat()
    return match.group(1).decode("ascii").strip()


def main() -> int:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    today = date.today().isoformat()

    psl = fetch(PSL_URL)
    if b"===BEGIN ICANN DOMAINS===" not in psl:
        print("public suffix list has no ICANN section marker; refusing", file=sys.stderr)
        return 1
    (DATA_DIR / "public_suffix_list.dat").write_bytes(psl)

    mime_db = fetch(MIME_DB_URL)
    parsed = json.loads(mime_db)
    extensions = {e.lower() for entry in parsed.values() for e in entry.get("extensions", ())}
    if "pdf" not in extensions or "docx" not in extensions:
        print(
            "mime-db payload does not look like the extension database; refusing", file=sys.stderr
        )
        return 1
    (DATA_DIR / "mime-db.json").write_bytes(mime_db)

    psl_digest = digest(psl)
    mime_digest = digest(mime_db)
    manifest = {
        "public_suffix_list": {
            "source_url": PSL_URL,
            "fetched": today,
            "upstream_version": psl_upstream_version(psl),
            "section": "icann",
            "sha256": psl_digest,
            "license": "MPL-2.0",
            "license_url": "https://mozilla.org/MPL/2.0/",
            "file": "public_suffix_list.dat",
            "note": (
                "Stored unmodified. Only the ICANN section is loaded at runtime (SPEC D21); "
                "the section is named in the version string because it changes recognition."
            ),
            "version": f"{psl_upstream_version(psl)}+icann/{psl_digest[:12]}",
        },
        "file_extensions": {
            "source_url": MIME_DB_URL,
            "fetched": today,
            "upstream_version": MIME_DB_VERSION,
            "sha256": mime_digest,
            "license": "MIT",
            "license_url": "https://github.com/jshttp/mime-db/blob/master/LICENSE",
            "file": "mime-db.json",
            "note": "Stored unmodified; the extension set is derived at load time.",
            "version": f"mime-db@{MIME_DB_VERSION}/{mime_digest[:12]}",
        },
    }
    (DATA_DIR / "registries.json").write_text(json.dumps(manifest, indent=2) + "\n")

    for name, entry in manifest.items():
        size = (DATA_DIR / entry["file"]).stat().st_size
        print(f"{name:20s} {entry['version']}  ({size:,} bytes)")
    print(f"extensions derived from mime-db: {len(extensions)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
