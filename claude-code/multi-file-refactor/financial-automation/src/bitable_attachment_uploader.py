from __future__ import annotations

import mimetypes
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from common.feishu import FeishuApiError, FeishuClient


class BitableAttachmentUploadError(FeishuApiError):
    """Raised when a bitable attachment upload cannot be completed."""


@dataclass
class BitableAttachmentUploadRequest:
    app_token: str
    attachment_paths: list[str]
    access_token: str | None = None
    endpoint: str = "https://open.feishu.cn"
    provider: str = "bitable_context_upload_user_identity"


@dataclass
class BitableAttachmentUploadResult:
    ok: bool
    status: str
    provider: str
    file_tokens: list[str]
    uploaded: list[dict[str, Any]]
    errors: list[dict[str, Any]]
    message: str


def build_bitable_attachment_upload_request(
    *,
    app_token: str,
    attachment_paths: list[str] | None,
    access_token: str | None = None,
    endpoint: str = "https://open.feishu.cn",
) -> BitableAttachmentUploadRequest | None:
    normalized_paths = [str(Path(path)) for path in (attachment_paths or []) if str(path).strip()]
    if not normalized_paths:
        return None
    return BitableAttachmentUploadRequest(
        app_token=app_token,
        attachment_paths=normalized_paths,
        access_token=access_token,
        endpoint=endpoint,
    )


def perform_bitable_attachment_upload(
    request: BitableAttachmentUploadRequest,
) -> BitableAttachmentUploadResult:
    if not request.access_token:
        raise BitableAttachmentUploadError(
            "Missing user access token for bitable-context attachment upload."
        )

    client = FeishuClient(endpoint=request.endpoint, user_access_token=request.access_token)

    uploaded: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    file_tokens: list[str] = []

    for raw_path in request.attachment_paths:
        path = Path(raw_path)
        if not path.exists():
            errors.append(
                {
                    "path": raw_path,
                    "code": "file_not_found",
                    "message": f"Attachment file does not exist: {raw_path}",
                }
            )
            continue
        try:
            uploaded_item = _upload_single_attachment(
                client=client, app_token=request.app_token, file_path=path
            )
            uploaded.append(uploaded_item)
            if uploaded_item.get("file_token"):
                file_tokens.append(str(uploaded_item["file_token"]))
        except FeishuApiError as exc:
            errors.append(
                {
                    "path": str(path),
                    "file_name": path.name,
                    "code": "upload_failed",
                    "message": str(exc),
                }
            )

    ok = not errors and bool(uploaded)
    return BitableAttachmentUploadResult(
        ok=ok,
        status="completed" if ok else "partial_failed",
        provider=request.provider,
        file_tokens=file_tokens,
        uploaded=uploaded,
        errors=errors,
        message=(
            "Uploaded attachments to bitable context with user identity."
            if ok
            else "One or more attachments failed during bitable-context upload."
        ),
    )


def build_attachment_field_value(file_tokens: list[str]) -> list[dict[str, str]]:
    return FeishuClient.build_attachment_field_value(file_tokens)


def _upload_single_attachment(
    *, client: FeishuClient, app_token: str, file_path: Path
) -> dict[str, Any]:
    """Upload one file via the shared client; reshape to the legacy item dict."""
    mime_type = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
    uploaded = client.upload_attachment(app_token=app_token, file_path=file_path)
    return {
        "path": str(file_path),
        "file_name": file_path.name,
        "file_token": uploaded["file_token"],
        "parent_type": uploaded["type"],
        "mime_type": mime_type,
        "size": uploaded["size"],
    }
