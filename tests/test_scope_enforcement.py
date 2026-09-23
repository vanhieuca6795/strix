"""Test tích hợp: scope guard cưỡng chế ở tầng tool.

Chạy qua đúng hàm `_enforce_scope` mà `repeat_request` gọi trước khi gửi request.
"""

from __future__ import annotations

import json
from typing import ClassVar

from strix.tools.proxy.tools import _enforce_scope


class _FakeCtx:
    """Bắt chước RunContextWrapper với scan_targets do runner bơm vào."""

    def __init__(self, scan_targets: list[str] | None) -> None:
        self.context = {"scan_targets": scan_targets} if scan_targets is not None else {}


class TestScopeEnforcementAtToolLayer:
    def test_in_scope_url_passes(self) -> None:
        ctx = _FakeCtx(["https://app.example.com"])
        assert _enforce_scope(ctx, "https://app.example.com/api/users", "repeat_request") is None

    def test_out_of_scope_url_blocked(self) -> None:
        ctx = _FakeCtx(["https://app.example.com"])
        result = _enforce_scope(ctx, "https://evil.com/exfil", "repeat_request")
        assert result is not None
        payload = json.loads(result)
        assert payload["success"] is False
        assert payload["error"] == "Out of authorized scope"
        # Lý do phải nêu rõ phạm vi cho phép, để agent tự sửa hướng.
        assert "app.example.com" in payload["detail"]

    def test_url_replacement_attack_blocked(self) -> None:
        # Kịch bản thật: request gốc trong phạm vi, nhưng modifications["url"]
        # bị đổi sang host khác. Đây chính là vector mà prompt không chặn được.
        ctx = _FakeCtx(["https://app.example.com"])
        stolen = "https://attacker.example.net/collect"
        result = _enforce_scope(ctx, stolen, "repeat_request")
        assert result is not None, "Đổi URL sang host khác PHẢI bị chặn"

    def test_ssrf_metadata_endpoint_blocked(self) -> None:
        ctx = _FakeCtx(["https://app.example.com"])
        result = _enforce_scope(
            ctx, "http://169.254.169.254/latest/meta-data/iam/", "repeat_request"
        )
        assert result is not None

    def test_internal_ip_blocked(self) -> None:
        ctx = _FakeCtx(["https://app.example.com"])
        assert _enforce_scope(ctx, "http://10.0.0.5/", "repeat_request") is not None

    def test_subdomain_not_authorized(self) -> None:
        ctx = _FakeCtx(["https://app.example.com"])
        assert _enforce_scope(ctx, "https://admin.example.com/", "repeat_request") is not None

    def test_path_prefix_confusion_blocked(self) -> None:
        ctx = _FakeCtx(["https://app.example.com/api"])
        assert _enforce_scope(ctx, "https://app.example.com/apix/", "repeat_request") is not None

    def test_path_within_authorized_prefix_allowed(self) -> None:
        ctx = _FakeCtx(["https://app.example.com/api"])
        assert _enforce_scope(ctx, "https://app.example.com/api/v1/users", "repeat_request") is None


class TestNoScopeMeansNoBlocking:
    """Không được chặn oan khi scan không có phạm vi mạng."""

    def test_source_only_scan_allows_all(self) -> None:
        # Quét source code: scan_targets là đường dẫn cục bộ, không có phạm vi mạng.
        ctx = _FakeCtx(["/workspace/myapp"])
        assert _enforce_scope(ctx, "https://anywhere.example.com/", "repeat_request") is None

    def test_empty_targets_allows_all(self) -> None:
        ctx = _FakeCtx([])
        assert _enforce_scope(ctx, "https://anywhere.example.com/", "repeat_request") is None

    def test_missing_key_allows_all(self) -> None:
        ctx = _FakeCtx(None)
        assert _enforce_scope(ctx, "https://anywhere.example.com/", "repeat_request") is None

    def test_ctx_without_context_attr_allows_all(self) -> None:
        assert _enforce_scope(object(), "https://anywhere.example.com/", "repeat_request") is None

    def test_malformed_targets_type_allows_all(self) -> None:
        class _Bad:
            context: ClassVar[dict[str, str]] = {"scan_targets": "not-a-list"}

        assert _enforce_scope(_Bad(), "https://anywhere.example.com/", "repeat_request") is None


class TestMixedScope:
    def test_one_network_target_plus_local_path(self) -> None:
        ctx = _FakeCtx(["/workspace/app", "https://api.example.com"])
        assert _enforce_scope(ctx, "https://api.example.com/v1/ping", "repeat_request") is None
        assert _enforce_scope(ctx, "https://other.example.com/", "repeat_request") is not None

    def test_multiple_authorized_hosts(self) -> None:
        ctx = _FakeCtx(["https://a.example.com", "https://b.example.com"])
        assert _enforce_scope(ctx, "https://a.example.com/x", "repeat_request") is None
        assert _enforce_scope(ctx, "https://b.example.com/y", "repeat_request") is None
        assert _enforce_scope(ctx, "https://c.example.com/z", "repeat_request") is not None

    def test_ip_target_scope(self) -> None:
        ctx = _FakeCtx(["https://10.10.11.234"])
        assert _enforce_scope(ctx, "https://10.10.11.234/admin", "repeat_request") is None
        assert _enforce_scope(ctx, "https://10.10.11.235/admin", "repeat_request") is not None


class TestMaliciousInputHandling:
    """Đầu vào không chuẩn hoá được phải bị chặn, không được cho qua."""

    def test_userinfo_host_confusion_blocked(self) -> None:
        ctx = _FakeCtx(["https://app.example.com"])
        assert (
            _enforce_scope(ctx, "https://app.example.com@evil.com/", "repeat_request") is not None
        )

    def test_encoded_traversal_blocked(self) -> None:
        ctx = _FakeCtx(["https://app.example.com"])
        assert (
            _enforce_scope(ctx, "https://app.example.com/%2e%2e/admin", "repeat_request")
            is not None
        )

    def test_backslash_obfuscation_blocked(self) -> None:
        ctx = _FakeCtx(["https://app.example.com"])
        assert (
            _enforce_scope(ctx, "https://app.example.com\\@evil.com", "repeat_request")
            is not None
        )

    def test_control_chars_blocked(self) -> None:
        ctx = _FakeCtx(["https://app.example.com"])
        assert _enforce_scope(ctx, "https://app.example.com/\x00", "repeat_request") is not None

    def test_non_http_scheme_blocked(self) -> None:
        ctx = _FakeCtx(["https://app.example.com"])
        assert _enforce_scope(ctx, "file:///etc/passwd", "repeat_request") is not None

    def test_valid_url_when_nothing_authorized_is_allowed(self) -> None:
        # Không có phạm vi thì không phán xét gì — kể cả URL dị thường.
        ctx = _FakeCtx([])
        assert _enforce_scope(ctx, "file:///etc/passwd", "repeat_request") is None
