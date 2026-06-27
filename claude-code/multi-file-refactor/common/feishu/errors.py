from __future__ import annotations


class FeishuApiError(RuntimeError):
    """Base exception for Feishu Open API failures.

    Covers non-zero API response codes, HTTP errors, and network errors.
    Subclasses ``RuntimeError`` so legacy ``except RuntimeError`` sites keep
    working while apps migrate to the shared client.
    """


class FeishuAuthError(FeishuApiError):
    """Raised when Feishu authentication fails (missing creds, token fetch)."""
