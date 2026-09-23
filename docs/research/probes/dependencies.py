"""Probes for the two dependencies whose behaviour shaped mail-dissect: Starlette and idna.

Run:  uv run --with python-multipart python docs/research/probes/dependencies.py

F11 and F12 in ../NOTES.md are produced by one function each here. Unlike
email_stdlib.py these need the project's locked environment, because the finding
is about the exact versions pinned in uv.lock. The one package added on the side,
python-multipart, is what Starlette's form handling needs and what the service
deliberately does not install. Read-only and offline: the requests go through an
in-process test client and never reach a socket.
"""

from __future__ import annotations

import sys

import idna
import python_multipart
import starlette
from starlette.applications import Starlette
from starlette.datastructures import UploadFile
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response
from starlette.routing import Route
from starlette.testclient import TestClient

CRLF = b"\r\n"
BOUNDARY = b"probe-boundary-7f3a"
MB = 1024 * 1024


def _banner(tag: str, title: str) -> None:
    print(f"\n=== {tag}: {title} ===")


def _form(raw: bytes, *, as_file: bool) -> bytes:
    """One `eml` part, built by hand so the bytes on the wire are exactly `raw`."""
    disposition = b'form-data; name="eml"' + (b'; filename="m.eml"' if as_file else b"")
    return (
        b"--" + BOUNDARY + CRLF
        + b"Content-Disposition: " + disposition + CRLF + CRLF
        + raw + CRLF
        + b"--" + BOUNDARY + b"--" + CRLF
    )  # fmt: skip


def f11_starlette_caps_and_decodes_form_fields() -> None:
    """F11: a non-file field is capped and text-decoded; a file part keeps its bytes."""
    _banner(
        "F11",
        f"Starlette {starlette.__version__} request.form(), "
        f"python-multipart {python_multipart.__version__}",
    )
    seen: dict[str, str | bytes] = {}

    async def endpoint(request: Request) -> Response:
        value = (await request.form())["eml"]
        seen["value"] = await value.read() if isinstance(value, UploadFile) else value
        return PlainTextResponse("ok")

    client = TestClient(Starlette(routes=[Route("/", endpoint, methods=["POST"])]))
    content_type = "multipart/form-data; boundary=" + BOUNDARY.decode()
    headers = b"From: a@example.com\r\n"
    cases = [
        ("field, ascii (control)", headers + b"\r\nbody", False),
        ("field, utf-8", headers + "Subject: café\r\n\r\nbody".encode(), False),
        ("field, one 8-bit byte", headers + b"Subject: caf\xe9\r\n\r\nbody", False),
        (
            "field, utf-8 + 8-bit",
            headers + "Subject: café\r\n".encode() + b"X: \xe9\r\n\r\nb",
            False,
        ),
        ("field, 2 MB", headers + b"\r\n" + b"x" * (2 * MB), False),
        ("file, 3 MB, 8-bit", headers + b"\r\n" + b"\xe9" * (3 * MB), True),
    ]
    values: dict[str, str | bytes] = {}
    for label, raw, as_file in cases:
        seen.clear()
        response = client.post(
            "/", content=_form(raw, as_file=as_file), headers={"content-type": content_type}
        )
        if response.status_code != 200:
            print(f"{label:24s} {response.status_code}  {response.text}")
            continue
        value = values[label] = seen["value"]
        if isinstance(value, bytes):
            print(f"{label:24s} 200  bytes, identical={value == raw}")
            continue
        back = {codec: value.encode(codec, "replace") == raw for codec in ("utf-8", "latin-1")}
        print(f"{label:24s} 200  str, utf-8 back={back['utf-8']}, latin-1 back={back['latin-1']}")
    # Two different messages, one string: the form value cannot be hashed back to either.
    same = values["field, utf-8"] == values["field, one 8-bit byte"]
    print(f"'caf\\xc3\\xa9' and 'caf\\xe9' arrive as the same str: {same}")


def f12_idna_refuses_hosts_mail_contains() -> None:
    """F12: which hosts `idna` refuses, next to two that it must accept."""
    _banner("F12", f"idna {idna.__version__}")
    print("encode(host, uts46=True, transitional=False):")
    for shown, host in (
        ("bücher.example", "bücher.example"),  # control: an IDN that has to encode
        ("a_b.example", "a_b.example"),
        ("ü_b.example", "ü_b.example"),
        ("-bad-.example", "-bad-.example"),
        ("<64 x ascii>.example", "x" * 64 + ".example"),
        ("ü<63 x ascii>.example", "ü" + "x" * 63 + ".example"),
    ):
        try:
            result = idna.encode(host, uts46=True, transitional=False).decode("ascii")
        except (idna.IDNAError, UnicodeError, ValueError) as exc:
            result = f"{type(exc).__name__}: {exc}"
        print(f"  {shown:24s} {result}")
    print("decode(host):")
    for host in ("xn--bcher-kva.example", "xn--zz.example"):
        try:
            result = idna.decode(host)
        except (idna.IDNAError, UnicodeError, ValueError) as exc:
            result = f"{type(exc).__name__}: {exc}"
        print(f"  {host:24s} {result}")


def main() -> int:
    print(f"python {sys.version}")
    f11_starlette_caps_and_decodes_form_fields()
    f12_idna_refuses_hosts_mail_contains()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
