# mail-dissect

A self-hosted HTTP service that takes one raw email message and returns a **deterministic
structural dissection** of it as JSON, plus the large parts as downloadable artifacts.

It answers one question — *what does this message contain and say?* — and deliberately does
not answer any other. No verdict, no score, no thresholds, no lists of "risky" anything: that
judgement depends on who is asking, and a service that makes it for you is useful to exactly
one consumer and an obstacle to the rest.

**Status: under construction.** The contract is settled and written down in
[`docs/SPEC.md`](docs/SPEC.md); the implementation is landing in stages, and
[`docs/spec-coverage.md`](docs/spec-coverage.md) tracks which acceptance case is proven by
which test. The full README — quickstart, endpoint reference, `curl` examples, the
configuration table and copy-paste unwrapper entries — lands with the last of them.

```bash
docker compose up -d
curl -fsS localhost:8000/v1/health
curl -fsS -X POST --data-binary @message.eml \
  -H 'content-type: message/rfc822' localhost:8000/v1/dissect
```

Licence: MIT. The bundled registry snapshots keep their own licences — see
[`src/mail_dissect/data/LICENSES.md`](src/mail_dissect/data/LICENSES.md).
