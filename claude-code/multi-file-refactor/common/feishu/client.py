from __future__ import annotations

import mimetypes
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from .auth import get_tenant_access_token
from .errors import FeishuApiError
from .http import get_json, post_json, post_multipart


class FeishuClient:
    """Feishu (Lark) Open API client — transport only, no business logic.

    Construct with either app credentials (auto-fetches and caches the
    tenant_access_token) or an explicit tenant/user access token::

        FeishuClient(app_id=..., app_secret=...)            # app identity
        FeishuClient(user_access_token=...)                 # user identity
        FeishuClient(tenant_access_token=...)               # pre-fetched token
    """

    def __init__(
        self,
        *,
        endpoint: str = "https://open.feishu.cn",
        app_id: str | None = None,
        app_secret: str | None = None,
        tenant_access_token: str | None = None,
        user_access_token: str | None = None,
        timeout: float = 60,
    ) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.app_id = app_id
        self.app_secret = app_secret
        self._tenant_access_token = tenant_access_token
        self._user_access_token = user_access_token
        self.timeout = timeout

    @property
    def access_token(self) -> str:
        """Resolve the active bearer token (user > tenant > auto-fetch)."""
        if self._user_access_token:
            return self._user_access_token
        if self._tenant_access_token:
            return self._tenant_access_token
        if self.app_id and self.app_secret:
            self._tenant_access_token = get_tenant_access_token(
                endpoint=self.endpoint, app_id=self.app_id, app_secret=self.app_secret
            )
            return self._tenant_access_token
        raise FeishuApiError(
            "No Feishu auth configured: provide (app_id + app_secret), "
            "tenant_access_token, or user_access_token."
        )

    def request(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Issue an Open API request against ``path`` with auth handled."""
        url = f"{self.endpoint}{path}"
        if query:
            url = f"{url}?{urlencode({k: v for k, v in query.items() if v is not None})}"
        if method == "GET":
            return get_json(url, headers=self._auth_headers(), timeout=self.timeout)
        if method == "POST":
            return post_json(url, body or {}, headers=self._auth_headers(), timeout=self.timeout)
        raise FeishuApiError(f"Unsupported HTTP method: {method}")

    # ------------------------------------------------------------------
    # bitable: read
    # ------------------------------------------------------------------

    def bitable_list_tables(self, app_token: str) -> list[dict[str, Any]]:
        return self._list_paginated(f"/open-apis/bitable/v1/apps/{app_token}/tables", page_size=100)

    def bitable_list_fields(self, app_token: str, table_id: str) -> list[dict[str, Any]]:
        return self._list_paginated(
            f"/open-apis/bitable/v1/apps/{app_token}/tables/{table_id}/fields", page_size=500
        )

    def bitable_list_records(self, app_token: str, table_id: str) -> list[dict[str, Any]]:
        return self._list_paginated(
            f"/open-apis/bitable/v1/apps/{app_token}/tables/{table_id}/records", page_size=500
        )

    # ------------------------------------------------------------------
    # bitable: write (auto-chunked; returns {"total", "records"})
    # ------------------------------------------------------------------

    def bitable_batch_create(
        self,
        app_token: str,
        table_id: str,
        records: list[dict[str, Any]],
        *,
        batch_size: int = 200,
    ) -> dict[str, Any]:
        return self._batch_write("batch_create", app_token, table_id, records, batch_size=batch_size)

    def bitable_batch_update(
        self,
        app_token: str,
        table_id: str,
        records: list[dict[str, Any]],
        *,
        batch_size: int = 200,
    ) -> dict[str, Any]:
        return self._batch_write("batch_update", app_token, table_id, records, batch_size=batch_size)

    # ------------------------------------------------------------------
    # attachments
    # ------------------------------------------------------------------

    def upload_attachment(self, app_token: str, file_path: str | Path) -> dict[str, Any]:
        """Upload one file to bitable context; returns file metadata."""
        path = Path(file_path)
        if not path.exists():
            raise FeishuApiError(f"Attachment file does not exist: {path}")
        parent_type = self._choose_parent_type(path)
        mime_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        response = post_multipart(
            f"{self.endpoint}/open-apis/drive/v1/medias/upload_all",
            fields={
                "file_name": path.name,
                "parent_type": parent_type,
                "parent_node": app_token,
                "size": str(path.stat().st_size),
            },
            file_field_name="file",
            file_name=path.name,
            file_bytes=path.read_bytes(),
            content_type=mime_type,
            headers=self._auth_headers(),
            timeout=self.timeout,
        )
        data = response.get("data", {}) if isinstance(response, dict) else {}
        file_token = str(data.get("file_token") or "")
        if not file_token:
            raise FeishuApiError(f"Feishu did not return file_token for {path.name}.")
        return {
            "file_token": file_token,
            "name": path.name,
            "type": parent_type,
            "size": path.stat().st_size,
        }

    @staticmethod
    def build_attachment_field_value(file_tokens: list[str]) -> list[dict[str, str]]:
        """Build a bitable attachment field value from file tokens."""
        return [{"file_token": token} for token in file_tokens if str(token).strip()]

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.access_token}"}

    def _list_paginated(self, path: str, *, page_size: int) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        page_token: str | None = None
        while True:
            response = self.request("GET", path, query={"page_size": page_size, "page_token": page_token})
            data = response.get("data") or {}
            items.extend(list(data.get("items") or []))
            if not data.get("has_more"):
                break
            page_token = data.get("page_token")
            if not page_token:
                break
        return items

    def _batch_write(
        self,
        action: str,
        app_token: str,
        table_id: str,
        records: list[dict[str, Any]],
        *,
        batch_size: int,
    ) -> dict[str, Any]:
        if not table_id:
            raise FeishuApiError("Missing Bitable table_id.")
        size = max(1, min(int(batch_size), 500))
        total = 0
        out: list[dict[str, Any]] = []
        for index in range(0, len(records), size):
            chunk = records[index : index + size]
            response = self.request(
                "POST",
                f"/open-apis/bitable/v1/apps/{app_token}/tables/{table_id}/records/{action}",
                body={"records": chunk},
            )
            data = response.get("data", {}) if isinstance(response, dict) else {}
            recs = data.get("records", []) if isinstance(data, dict) else []
            total += len(recs) if recs else len(chunk)
            out.extend(recs)
        return {"total": total, "records": out}

    @staticmethod
    def _choose_parent_type(path: Path) -> str:
        return (
            "bitable_image"
            if path.suffix.lower() in {".jpg", ".jpeg", ".png", ".webp", ".bmp", ".gif"}
            else "bitable_file"
        )
