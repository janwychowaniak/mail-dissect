# mail-dissect

[![ci](https://github.com/janwychowaniak/mail-dissect/actions/workflows/ci.yml/badge.svg)](https://github.com/janwychowaniak/mail-dissect/actions/workflows/ci.yml)
[![gitleaks](https://github.com/janwychowaniak/mail-dissect/actions/workflows/gitleaks.yml/badge.svg)](https://github.com/janwychowaniak/mail-dissect/actions/workflows/gitleaks.yml)

A self-hosted HTTP service that takes one raw email message and returns a **deterministic
structural dissection** of it as JSON, plus the large parts as downloadable artifacts.

It answers one question — *what does this message contain and say?* — and it stops there.

## Why

Every team that works with mail ends up re-implementing the same things, each slightly
differently and each slightly wrong: descending into forwarded messages, decoding headers that
lie about their charset, pulling links out of HTML that was never valid, telling an attachment
from an inline image. This service does that once, the same way every time.

- **Every header, decomposed in full** — every address header split into display name, address,
  local part and domain; every `Received` hop; every method in `Authentication-Results`, not a
  chosen three.
- **Forwarded messages are messages.** They appear in `messages[]` with their own bodies,
  links and candidates, at any depth — and the `eml` artifact hands back the **original bytes**,
  so the hash you compute matches the hash anyone else computes from the same mail.
- **Links and auto-loaded resources are separate lists**, because they are two different events
  in the recipient's client.
- **Indicator candidates in one canonical list** — URLs, domains, addresses, IPs, hashes,
  filenames — deduplicated, counted, and each one pointing back at the place it came from.
- **Deterministic.** The same message, the same limits, the same registry versions: the same
  bytes out, array order included.

## What it deliberately does not do

**It does not judge.** No score, no verdict, no thresholds, no lists of "risky extensions" or
"free mail providers". That is not modesty — it is what makes the output usable by more than
one consumer. The same domain is internal to you and foreign to the next team; the same
attachment type is routine in one process and an alarm in another. A service that decides for
you is a service the next consumer has to work around.

What you get instead is **facts and representations**: what the message contains, what it says,
and how it renders — with the flags that say when something could not be read. The judgement
stays where it belongs, and you can change your mind about it without changing this service.

**It makes no outbound connections** beyond the two optional tools you configure. No DNS, no
reputation lookups, no fetching of anything a message points at. It runs in a network with no
route out, and a CI job proves that on every commit.

## Quickstart

```bash
docker compose up -d
curl -fsS localhost:8000/v1/health

curl -fsS -X POST --data-binary @message.eml \
  -H 'content-type: message/rfc822' localhost:8000/v1/dissect
```

The compose file brings up all three containers — the service plus both optional tools — on a
network with no route out. The service alone needs no configuration at all:

```bash
docker run -d -p 127.0.0.1:8000:8000 --tmpfs /tmp:size=256m \
  ghcr.io/janwychowaniak/mail-dissect:latest
```

## API

| Endpoint | Role |
| --- | --- |
| `POST /v1/dissect` | the message, as `multipart/form-data` with field `eml` or as raw bytes with `Content-Type: message/rfc822` |
| `GET /v1/artifact/{dissect_id}/{artifact_id}` | raw artifact bytes |
| `GET /v1/health` | liveness, tool states and registry versions |

Both input channels are equal and give identical results for identical bytes.

```bash
# raw bytes
curl -X POST --data-binary @message.eml -H 'content-type: message/rfc822' \
  localhost:8000/v1/dissect

# or as a form field
curl -X POST -F eml=@message.eml localhost:8000/v1/dissect
```

### The response, abridged

```jsonc
{
  "ok": true,
  "dissect_id": "q0F1siewpvLMF-IlPjotLw",
  "source": { "size": 633, "md5": "e2db79…", "sha1": "e4c50d…", "sha256": "8dd76d…" },
  "messages": [{
    "index": 0, "depth": 0,
    "headers": { "from": ["Sender <sender@example.net>"], "subject": ["Zamówienie"] },
    "addresses": { "from": [{ "display_name": "Sender", "address": "sender@example.net",
                              "local_part": "sender", "domain": "example.net" }] },
    "auth": [{ "method": "spf", "result": "pass", "params": {"smtp.mailfrom": "example.net"} },
             { "method": "dkim", "result": "fail", "params": {"header.d": "example.net"} }],
    "received": [{ "from_host": "mx.example.net", "from_ip": "192.0.2.10",
                   "by_host": "in.example.org", "with": "ESMTPS", "id": "AB1",
                   "for": null, "timestamp": "Tue, 1 Sep 2026 10:00:00 +0000" }],
    "body": { "text": "Plain version: visit bit.ly/xyz",
              "html": "<p>HTML version: …</p>",
              "text_from_html": "HTML version: click",
              "text_artifact_id": "pmHZTJ…", "html_artifact_id": "CujBUd…",
              "text_from_html_artifact_id": "PMzKX5…",
              "text_part_index": 1, "html_part_index": 2 },
    "mime_parts": [ /* every part, in tree order — the index is the only identifier */ ],
    "links":     [ /* anchors: something the recipient must click */ ],
    "resources": [ /* loaded automatically when the message is opened */ ],
    "observables": [{ "value": "bit.ly/xyz", "value_raw": "bit.ly/xyz", "type": "url",
                      "subtype": null, "defanged": false, "ambiguous": false,
                      "occurrences": 1,
                      "sources": [{"kind": "body_text", "part_index": 1}] }],
    "attachments": [ /* part_index, hashes, declared vs detected type, artifact ids */ ]
  }],
  "artifacts": [{ "artifact_id": "pmHZTJ…", "message_index": 0, "kind": "body_text",
                  "filename": "0-body.txt", "mime": "application/octet-stream",
                  "size": 31, "sha256": "…" }],
  "tools": { "tika": "disabled", "renderer": "disabled" },
  "flags": []
}
```

The full contract, including every closed value set and the reasoning behind it, is in
[`docs/SPEC.md`](docs/SPEC.md).

### Two things worth knowing before you read `observables[]`

**A `.com` or `.org` domain also produces a `filename` candidate**, flagged `ambiguous: true`.
**60 of the 1441 single-label public suffixes are also file extensions**, and the 60 include
`com` (the extension of `application/x-msdownload`) and `org` (`text/x-org`). Two registries
genuinely claim the string, and the service refuses to guess which reading you meant — so
expect this on nearly every domain in ordinary mail, not as a corner case. Drop one side with
a single condition — `o["ambiguous"] and o["type"] == "filename"` — and keep the signal for
`raport.zip`, where it matters.

**Attachment filenames are not candidates.** They are a fact in `attachments[]`. What appears
in `observables[]` is what the message *says*, not what it *carries*; the same distinction
keeps a hash written in the body apart from a hash computed over an attachment's bytes.

### Artifacts

Large things are a separate request rather than base64 in the JSON, because consumers pass
these responses through layers that handle very long strings badly.

```bash
curl -fsS -o body.html \
  localhost:8000/v1/artifact/$DISSECT_ID/$ARTIFACT_ID
```

Artifacts are **ephemeral** (30 minutes by default, and less if the service restarts) and their
identifiers are the only thing protecting them, so they are unguessable and never logged.
Fetch them promptly, and treat `404` and `410` as ordinary answers rather than failures.

Kinds: `eml`, `headers`, `body_text`, `body_html`, `body_text_from_html`, `attachment`,
`attachment_text`, `screenshot`.

## Errors

One envelope, one machine-readable code, and `dissect_id` present even on failure so you can
correlate it with your own logs.

```json
{"ok": false, "dissect_id": "…", "error": {"code": "UNPARSABLE", "message": "…"}}
```

| Code | HTTP | When |
| --- | --- | --- |
| `BAD_REQUEST` | 400 | no message on input, empty body, unknown `Content-Type` |
| `TOO_LARGE` | 413 | over `MAX_MESSAGE_BYTES`, refused before parsing |
| `UNPARSABLE` | 422 | not one valid header before the first empty line |
| `ARTIFACT_NOT_FOUND` | 404 | unknown ids, an artifact from a previous process life, or a listing request |
| `ARTIFACT_EXPIRED` | 410 | created in this process life, and its lifetime passed |
| `INTERNAL` | 500 | a failure on our side |

**A damaged message is not an error.** Anything that falls apart after the first header comes
back as HTTP 200 with a flag: `malformed_mime`, `encoding_fallback`, `attachment_unreadable`,
`truncated`, `artifact_store_failed`. A problem with an optional tool is not an error either —
it shows up in `tools{}` and changes nothing else.

## Configuration

Environment variables only. **No variable is required** — the image starts with working
defaults. See [`.env.example`](.env.example) for the whole surface.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TIKA_URL` | *(empty)* | Apache Tika Server, for text inside documents. Empty means `disabled` |
| `SCREENSHOT_URL` | *(empty)* | a Gotenberg-compatible screenshot route |
| `MAX_MESSAGE_BYTES` | 50 MB | input size; over it, `TOO_LARGE` before parsing |
| `MAX_ATTACHMENT_BYTES` | 25 MB | one attachment after decoding; over it, hashes but no artifact |
| `MAX_NESTING_DEPTH` | 5 | how deep to follow forwarded messages |
| `MAX_MIME_PARTS` | 500 | parts per dissection, established before the tree is built |
| `MAX_INLINE_BODY_BYTES` | 256 KB | content in the response; above it, artifact only |
| `DISSECT_TIMEOUT_SECONDS` | 60 | the whole dissection, dependency calls included |
| `TIKA_TIMEOUT_SECONDS` | 20 | one extraction call |
| `SCREENSHOT_TIMEOUT_SECONDS` | 30 | one render |
| `HEALTH_PROBE_TIMEOUT_SECONDS` | 2 | one dependency probe from `/v1/health` |
| `HEALTH_CACHE_TTL_SECONDS` | 10 | how long health may serve a remembered tool state |
| `ARTIFACT_TTL_SECONDS` | 1800 | artifact lifetime — an upper bound, not a guarantee |
| `ARTIFACT_DIR` | `/tmp` | artifact store; mount it as `tmpfs` |
| `UNWRAPPERS` | *(empty)* | the link-unwrapper table, below |
| `EXTRA_FILE_EXTENSIONS` | *(empty)* | extensions your world has and the registry does not |

**Memory.** One request peaks at roughly the input size plus the parser's representation of it
plus the largest decoded attachment; measured at the default limits, **452 MB for a 47 MB
message carrying a 24 MB attachment**. Three things multiply it: the limits you set,
concurrent requests, and up to four concurrent calls to the optional tools (a constant, not a
variable). Size the container from those, not from your typical message.

### Unwrapping rewritten links

Mail filters replace addresses in the content with their own. Tell the service how to reverse
the ones you have; it ships with **none**, because a ready-made list would be a choice about
whose filters matter. Anything not in your table passes through untouched, and nothing is ever
resolved over the network.

```bash
# The shape of a query-parameter wrapper, e.g. https://…/?url=<percent-encoded target>
UNWRAPPERS='[
  {"host_suffix":"safelinks.protection.outlook.com","source":"query:url","decoder":"percent"}
]'

# The shape of a path-segment wrapper, e.g. https://gateway.example/r/<base64url target>/
UNWRAPPERS='[
  {"host_suffix":"gateway.example","source":"path_segment:1","decoder":"base64url",
   "strip_suffix":"/"}
]'
```

**Write your own entries from your own mail rather than copying a vendor list.** Take one
rewritten link, find where the original address sits in it — a query parameter or a path
segment — and note how it is encoded. That is the entry. Wrapper formats differ between
products and change between versions, so a list published here would be wrong for somebody on
the day they read it.

`source` is `query:<parameter>` or `path_segment:<zero-based index>`; `decoder` is `percent`,
`base64`, `base64url` or `none`; optional `strip_prefix` and `strip_suffix` trim the extracted
value. Unwrapping repeats to a fixed point, `rewritten_from` carries the address that actually
stood in the message, and an entry that matches but cannot extract its target sets
`unwrap_failed: true` rather than pretending there was nothing to unwrap. **Malformed
`UNWRAPPERS` stops the service from starting** — silently ignoring it would be worse.

### Extensions the registry does not know

The extension registry is keyed by media type, so formats without a registered one — `scr`,
`pif`, `hta`, `ps1`, `vbs`, `wsf` — are absent from it. Add the ones that matter in your
world; the service ships none, and the value is reported in `/v1/health` because it changes
what the same string is recognised as.

```bash
EXTRA_FILE_EXTENSIONS=scr,pif,hta,ps1,psm1,vbs,vbe,jse,wsf,wsh,cmd,reg
```

## Optional tools

Both are soft dependencies: without them the dissection is poorer, never wrong, and `tools{}`
says which. They must be reachable **for the service**, not for you.

- **`TIKA_URL`** — `apache/tika` works with no adapter. Document attachments are sent to it,
  never images or archives; the text comes back as an `attachment_text` artifact and its
  candidates join the same `observables[]` list as everything else.
- **`SCREENSHOT_URL`** — a Gotenberg screenshot route works with no adapter. Every message
  with an HTML body is rendered, nested ones included. The service does not render in-process
  on purpose: parsing hostile HTML and *running* it are different risk profiles.

  **Configure the renderer with scripting off and an allow-list, and copy the flags from
  `compose.yml`.** Mail clients do not run scripts either, so a render without them is more
  faithful, not less. The allow-list matters more than it looks: with
  `--chromium-allow-list=^file:///tmp/.*` a message that embeds `<img src="http://attacker…">`
  produces **no request at all** — measured against a listener the renderer could otherwise
  reach — so the reader is protected from a beacon even if they never isolate the network.
  Do **not** reach for `--chromium-deny-list=.*` instead: Gotenberg serves the page it is
  rendering from a `file:///tmp/…` URL of its own, so that rule denies the document and every
  render answers 403.

### Verified tool versions

This release was tested against **`apache/tika:3.2.3.0`** and **`gotenberg/gotenberg:8.37.0`**
— the versions `compose.yml` pins, exercised end to end by `tests/test_live_tools.py`. Pin
those rather than `latest`: the call shapes are stable, but the renderer's own flags are not
something to take on trust.

The digests those tags resolved to, for anyone pulling from a registry:

```
apache/tika@sha256:c0154cb95587cde64be74f35ada1a2bd7892219f3f0ac3c9dc6cab34046b3573
gotenberg/gotenberg@sha256:f29984bd1e226bf1b93ba90af06000afa8b315853e99d27b9aaa41b93f15c769
ghcr.io/janwychowaniak/mail-dissect@sha256:cc697396bb70ee38ea8d688750c6a385cbbaf029b91caf1fa967c503ee5cba92
```

**Moving the images to a host with no registry access.** A digest verifies a pull; on a host
that cannot reach a registry there is nothing for it to verify against. Two things matter
instead:

```bash
# On a machine that can pull. BY TAG, never by image ID.
docker save ghcr.io/janwychowaniak/mail-dissect:0.1.1 apache/tika:3.2.3.0   gotenberg/gotenberg:8.37.0 -o mail-dissect-bundle.tar
sha256sum mail-dissect-bundle.tar        # compare this on the other side

# On the target host.
docker load -i mail-dissect-bundle.tar
docker image inspect ghcr.io/janwychowaniak/mail-dissect:0.1.1 --format '{{.RepoTags}}'
```

**`docker save <image id>` produces an archive that loads with no tags at all**, and an
untagged image is invisible to `docker compose`, which then tries to pull it and fails — the
one failure mode that only appears on the host that cannot pull. Saving by tag preserves it.

**The digest does not survive the transfer** — it is a property of the pull. Measured twice,
independently, on Docker 29.1.3 with the `overlay2` image store: `RepoDigests` comes back
**empty** after `load` while `RepoTags` is preserved. Both measurements had to remove the
image first, because a `load` over an image that is still present is a no-op that leaves the
old metadata in place and reads as "the digest survived". Whether the containerd image store
behaves differently is untested. Compare the checksum of the archive instead — it is the
artifact both sides actually hold. The one in `compose.yml` is deliberate —
`--chromium-allow-list=^file:///.*` rather than a deny-list of everything, because Gotenberg
renders the uploaded page from a `file:///` URL of its own and denying `.*` denies that too,
turning every render into a `403`.

The minimal Tika image is the right one here: extracting text from office documents does not
need OCR, and every extra parser is more surface reading a hostile file.

## Registries

Two snapshots are baked into the image and never fetched at runtime: the
[Public Suffix List](https://publicsuffix.org/) (ICANN section only) and
[mime-db](https://github.com/jshttp/mime-db). Their versions are in `/v1/health`, because
recognition depends on them — a new public suffix changes the classification of the same
string. They keep their own licences; see
[`src/mail_dissect/data/LICENSES.md`](src/mail_dissect/data/LICENSES.md).

## Deployment notes

The service is **unauthenticated by design** and meant for an internal network of known
composition. Publish it on the loopback interface, as the compose file does, and put an
authenticating layer in front of it anywhere else.

Mount `ARTIFACT_DIR` as `tmpfs`: other people's correspondence has no reason to touch
persistent storage, and on shutdown it disappears with the memory.

The artifact store is local to the process, so several replicas need either a shared directory
or routing that keeps a `dissect_id` on the instance that produced it.

## Development

```bash
uv sync --frozen
uv run pytest -q                        # offline by default, and CI depends on that
uv run ruff check . && uv run mypy --strict src
DOCKER_BUILDKIT=0 docker build -t mail-dissect:dev .
```

`docs/SPEC.md` is the source of truth; `docs/spec-coverage.md` maps every requirement and
acceptance case to the test that proves it. Test material is synthetic only — the repository
contains no third-party correspondence and never will.

## Licence

MIT. The bundled registry snapshots keep their own.
