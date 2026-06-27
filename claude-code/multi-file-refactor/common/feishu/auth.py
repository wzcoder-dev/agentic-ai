from __future__ import annotations

import json
from pathlib import Path

from .errors import FeishuAuthError
from .http import post_json


def get_tenant_access_token(*, endpoint: str, app_id: str, app_secret: str) -> str:
    """Fetch a tenant_access_token using app credentials."""
    if not app_id or not app_secret:
        raise FeishuAuthError("Missing Feishu app_id or app_secret.")
    response = post_json(
        f"{endpoint.rstrip('/')}/open-apis/auth/v3/tenant_access_token/internal",
        {"app_id": app_id, "app_secret": app_secret},
    )
    token = str(response.get("tenant_access_token") or "")
    if not token:
        raise FeishuAuthError("Failed to obtain tenant_access_token from Feishu.")
    return token


def load_user_access_token(token_file: str | Path) -> str:
    """Load a cached user access_token from a JSON file (OAuth handoff artifact)."""
    payload = json.loads(Path(token_file).read_text(encoding="utf-8") or "{}")
    token = str(payload.get("access_token") or "").strip()
    if not token:
        raise FeishuAuthError(f"No access_token found in token file: {token_file}")
    return token
