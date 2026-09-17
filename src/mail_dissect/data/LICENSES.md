# Bundled registry snapshots

These two files are third-party data shipped inside the image. They keep their own licences,
which are not the project's MIT licence. Provenance, versions and digests are in
[`registries.json`](registries.json); `scripts/fetch_registries.py` is what produced them.

Both are stored **unmodified**. Neither is ever fetched at runtime — the service has no route
out, and updating a registry is a new image release (SPEC §12).

## `public_suffix_list.dat`

- Source: <https://publicsuffix.org/list/public_suffix_list.dat>
- Licence: **MPL-2.0** — <https://mozilla.org/MPL/2.0/>
- Copyright: Mozilla Foundation and the Public Suffix List contributors.
- Only the ICANN section is loaded at runtime (SPEC `[D21]`); the file itself is shipped whole
  so that what we distribute is what upstream published.

## `mime-db.json`

- Source: <https://cdn.jsdelivr.net/npm/mime-db@1.54.0/db.json> (jshttp/mime-db)
- Licence: **MIT** — <https://github.com/jshttp/mime-db/blob/master/LICENSE>
- Copyright: 2014 Jonathan Ong, 2015-2022 Douglas Christopher Wilson.
- Only the extension set is derived from it; the media types themselves are not used for
  detection (SPEC §7.1 detection works from content signatures).
