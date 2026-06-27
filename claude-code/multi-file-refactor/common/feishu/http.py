from __future__ import annotations

import json
import uuid
from typing import Any
from urllib import error, request

from .errors import FeishuApiError


def get_json(url: str, *, headers: dict[str, str] | None = None, timeout: float = 60) -> dict[str, Any]:
    """GET ``url`` and return the parsed JSON response."""
    req = request.Request(url, headers=headers or {}, method="GET")
    return _read_json_response(req, timeout=timeout)


def post_json(
    url: str,
    payload: dict[str, Any],
    *,
    headers: dict[str, str] | None = None,
    timeout: float = 60,
) -> dict[str, Any]:
    """POST ``payload`` as JSON and return the parsed JSON response."""
    body = json.dumps(payload).encode("utf-8")
    merged_headers = {"Content-Type": "application/json; charset=utf-8", **(headers or {})}
    req = request.Request(url, data=body, headers=merged_headers, method="POST")
    return _read_json_response(req, timeout=timeout)


def post_multipart(
    url: str,
    *,
    fields: dict[str, str],
    file_field_name: str,
    file_name: str,
    file_bytes: bytes,
    content_type: str,
    headers: dict[str, str] | None = None,
    timeout: float = 60,
) -> dict[str, Any]:
    """POST ``file_bytes`` as ``multipart/form-data`` and return parsed JSON."""
    boundary = f"----OpenClawBoundary{uuid.uuid4().hex}"
    body = bytearray()

    for key, value in fields.items():
        body.extend(f"--{boundary}\r\n".encode("utf-8"))
        body.extend(f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode("utf-8"))
        body.extend(str(value).encode("utf-8"))
        body.extend(b"\r\n")

    body.extend(f"--{boundary}\r\n".encode("utf-8"))
    body.extend(
        (
            f'Content-Disposition: form-data; name="{file_field_name}"; '
            f'filename="{file_name}"\r\n'
        ).encode("utf-8")
    )
    body.extend(f"Content-Type: {content_type}\r\n\r\n".encode("utf-8"))
    body.extend(file_bytes)
    body.extend(b"\r\n")
    body.extend(f"--{boundary}--\r\n".encode("utf-8"))

    merged_headers = {"Content-Type": f"multipart/form-data; boundary={boundary}", **(headers or {})}
    req = request.Request(url, data=bytes(body), headers=merged_headers, method="POST")
    return _read_json_response(req, timeout=timeout)


def _read_json_response(req: request.Request, *, timeout: float = 60) -> dict[str, Any]:
    """Read ``req``, decode JSON, and raise :class:`FeishuApiError` on non-zero code."""
    try:
        with request.urlopen(req, timeout=timeout) as response:
            raw_body = response.read().decode("utf-8")
    except error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise FeishuApiError(f"Feishu API error {exc.code}: {body}") from exc
    except error.URLError as exc:
        raise FeishuApiError(f"Failed to reach Feishu API: {exc}") from exc

    payload = json.loads(raw_body or "{}")
    code = int(payload.get("code", 0) or 0)
    if code != 0:
        message = payload.get("msg") or payload.get("message") or "unknown error"
        raise FeishuApiError(f"Feishu API returned code {code}: {message}")
    return payload
