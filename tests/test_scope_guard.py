"""Test cho scope_guard — tập trung vào các vector vòng qua phạm vi."""

from __future__ import annotations

import pytest

from strix.utils.scope_guard import (
    authorized_network_targets,
    canonicalize_target,
    check_target_in_scope,
    target_within,
)


class TestCanonicalizeUrl:
    def test_plain_https(self) -> None:
        result = canonicalize_target("https://app.example.com")
        assert result is not None
        assert result.origin == ("https", "app.example.com", 443)
        assert result.segments == ()

    def test_path_segments(self) -> None:
        result = canonicalize_target("https://app.example.com/api/v1/users")
        assert result is not None
        assert result.segments == ("api", "v1", "users")

    def test_explicit_port(self) -> None:
        result = canonicalize_target("http://app.example.com:8080/admin")
        assert result is not None
        assert result.origin == ("http", "app.example.com", 8080)

    def test_host_casefolded_and_dot_stripped(self) -> None:
        result = canonicalize_target("https://APP.Example.COM./x")
        assert result is not None
        assert result.host == "app.example.com"

    def test_default_port_per_scheme(self) -> None:
        http = canonicalize_target("http://a.example.com")
        https = canonicalize_target("https://a.example.com")
        assert http is not None and http.port == 80
        assert https is not None and https.port == 443

    def test_ip_target(self) -> None:
        result = canonicalize_target("https://10.10.11.234/path")
        assert result is not None
        assert result.host == "10.10.11.234"


class TestCanonicalizeHostForm:
    def test_bare_host(self) -> None:
        result = canonicalize_target("app.example.com")
        assert result is not None
        assert result.kind == "host"
        assert result.host == "app.example.com"
        assert result.port == 0

    def test_host_with_port(self) -> None:
        result = canonicalize_target("app.example.com:8443")
        assert result is not None
        assert result.kind == "host"
        assert result.port == 8443

    def test_bare_ip(self) -> None:
        result = canonicalize_target("10.10.11.234")
        assert result is not None
        assert result.host == "10.10.11.234"


class TestCanonicalizeRejectsMaliciousForms:
    """Các dạng được dùng để lách so khớp phạm vi — phải bị từ chối."""

    def test_userinfo_rejected(self) -> None:
        # https://app.example.com@evil.com/ thực chất trỏ tới evil.com.
        assert canonicalize_target("https://app.example.com@evil.com/") is None

    def test_password_userinfo_rejected(self) -> None:
        assert canonicalize_target("https://user:pass@evil.com/") is None

    def test_fragment_rejected(self) -> None:
        assert canonicalize_target("https://app.example.com/#@evil.com") is None

    def test_backslash_rejected(self) -> None:
        assert canonicalize_target("https://app.example.com\\@evil.com") is None

    def test_control_characters_rejected(self) -> None:
        assert canonicalize_target("https://app.example.com/\x00admin") is None
        assert canonicalize_target("https://app.example.com/\x1b[31m") is None

    def test_dot_dot_segment_rejected(self) -> None:
        assert canonicalize_target("https://app.example.com/api/../admin") is None

    def test_encoded_dot_dot_rejected(self) -> None:
        # %2e%2e giải mã thành '..' -> phải bị chặn.
        assert canonicalize_target("https://app.example.com/api/%2e%2e/admin") is None

    def test_double_encoded_dot_dot_rejected(self) -> None:
        assert canonicalize_target("https://app.example.com/api/%252e%252e/admin") is None

    def test_dot_segment_with_parameter_rejected(self) -> None:
        # '..;x' — tham số path không được phép che dấu '..'.
        assert canonicalize_target("https://app.example.com/api/..;/admin") is None

    def test_non_http_scheme_rejected(self) -> None:
        assert canonicalize_target("file:///etc/passwd") is None
        assert canonicalize_target("gopher://app.example.com/") is None
        assert canonicalize_target("ftp://app.example.com/") is None

    def test_leading_trailing_whitespace_rejected(self) -> None:
        assert canonicalize_target(" https://app.example.com") is None
        assert canonicalize_target("https://app.example.com ") is None

    def test_invalid_port_rejected(self) -> None:
        assert canonicalize_target("https://app.example.com:99999/") is None
        assert canonicalize_target("https://app.example.com:0/") is None

    def test_empty_rejected(self) -> None:
        assert canonicalize_target("") is None
        assert canonicalize_target("   ") is None


class TestTargetWithin:
    def test_same_origin_subpath_allowed(self) -> None:
        allowed = canonicalize_target("https://app.example.com/api")
        candidate = canonicalize_target("https://app.example.com/api/v1/users")
        assert allowed is not None and candidate is not None
        assert target_within(allowed, candidate)

    def test_exact_origin_allowed(self) -> None:
        allowed = canonicalize_target("https://app.example.com")
        candidate = canonicalize_target("https://app.example.com/anything/here")
        assert allowed is not None and candidate is not None
        assert target_within(allowed, candidate)

    def test_different_host_rejected(self) -> None:
        allowed = canonicalize_target("https://app.example.com")
        candidate = canonicalize_target("https://evil.com/app")
        assert allowed is not None and candidate is not None
        assert not target_within(allowed, candidate)

    def test_subdomain_not_implied(self) -> None:
        # app.example.com không bao hàm admin.example.com.
        allowed = canonicalize_target("https://app.example.com")
        candidate = canonicalize_target("https://admin.example.com")
        assert allowed is not None and candidate is not None
        assert not target_within(allowed, candidate)

    def test_sibling_path_prefix_not_confused(self) -> None:
        # /api KHÔNG được coi là chứa /apix (so theo đoạn, không theo ký tự).
        allowed = canonicalize_target("https://app.example.com/api")
        candidate = canonicalize_target("https://app.example.com/apix/admin")
        assert allowed is not None and candidate is not None
        assert not target_within(allowed, candidate)

    def test_path_escape_rejected(self) -> None:
        allowed = canonicalize_target("https://app.example.com/api")
        candidate = canonicalize_target("https://app.example.com/admin")
        assert allowed is not None and candidate is not None
        assert not target_within(allowed, candidate)

    def test_different_port_rejected(self) -> None:
        allowed = canonicalize_target("https://app.example.com")
        candidate = canonicalize_target("https://app.example.com:8443/admin")
        assert allowed is not None and candidate is not None
        assert not target_within(allowed, candidate)

    def test_scheme_downgrade_rejected(self) -> None:
        allowed = canonicalize_target("https://app.example.com")
        candidate = canonicalize_target("http://app.example.com")
        assert allowed is not None and candidate is not None
        assert not target_within(allowed, candidate)

    def test_host_form_matches_same_host(self) -> None:
        allowed = canonicalize_target("app.example.com")
        candidate = canonicalize_target("app.example.com")
        assert allowed is not None and candidate is not None
        assert target_within(allowed, candidate)

    def test_host_form_rejects_other_host(self) -> None:
        allowed = canonicalize_target("app.example.com")
        candidate = canonicalize_target("evil.com")
        assert allowed is not None and candidate is not None
        assert not target_within(allowed, candidate)


class TestAuthorizedNetworkTargets:
    def test_filters_out_local_paths(self) -> None:
        authorized = ["/workspace/billing", "https://app.example.com"]
        result = authorized_network_targets(authorized)
        assert len(result) == 1
        assert result[0].host == "app.example.com"

    def test_keeps_host_and_ip_forms(self) -> None:
        authorized = ["app.example.com", "10.10.11.234", "https://api.example.com"]
        assert len(authorized_network_targets(authorized)) == 3

    def test_all_local_returns_empty(self) -> None:
        assert authorized_network_targets(["/workspace/x", "/tmp/y"]) == []

    def test_skips_blank_and_non_string(self) -> None:
        assert authorized_network_targets(["", "  ", "/workspace/x"]) == []


class TestCheckTargetInScope:
    def test_in_scope_url_allowed(self) -> None:
        ok, reason = check_target_in_scope(
            "https://app.example.com/login", ["https://app.example.com"]
        )
        assert ok and reason == ""

    def test_out_of_scope_url_blocked(self) -> None:
        ok, reason = check_target_in_scope("https://evil.com/", ["https://app.example.com"])
        assert not ok
        assert "NGOÀI phạm vi" in reason
        assert "app.example.com" in reason

    def test_no_network_scope_allows_everything(self) -> None:
        # Scan chỉ đọc source code: không có phạm vi mạng nào để cưỡng chế.
        ok, reason = check_target_in_scope("https://anywhere.com/", ["/workspace/code"])
        assert ok and reason == ""

    def test_empty_authorized_allows_everything(self) -> None:
        ok, _ = check_target_in_scope("https://anywhere.com/", [])
        assert ok

    def test_malicious_form_blocked_even_if_host_matches(self) -> None:
        # userinfo trỏ host khác -> không được lọt qua chỉ vì chuỗi có chứa host đúng.
        ok, reason = check_target_in_scope(
            "https://app.example.com@evil.com/", ["https://app.example.com"]
        )
        assert not ok
        assert "không chuẩn hoá được" in reason

    def test_multiple_authorized_targets(self) -> None:
        authorized = ["https://app.example.com", "https://api.example.com"]
        assert check_target_in_scope("https://api.example.com/v1", authorized)[0]
        assert check_target_in_scope("https://app.example.com/", authorized)[0]
        assert not check_target_in_scope("https://third.example.com/", authorized)[0]

    def test_reason_lists_allowed_scope(self) -> None:
        authorized = ["https://a.example.com", "https://b.example.com"]
        _, reason = check_target_in_scope("https://evil.com/", authorized)
        assert "a.example.com" in reason and "b.example.com" in reason


class TestRealWorldBypassAttempts:
    """Các kịch bản vòng qua thực tế mà pentester hay dùng."""

    @pytest.mark.parametrize(
        "bypass",
        [
            "https://app.example.com.evil.com/",
            "https://evil.com/app.example.com/",
            "https://appXexample.com/",
            "https://app.example.com:443@evil.com/",
            "https://app.example.com%00.evil.com/",
        ],
    )
    def test_host_confusion_variants_blocked(self, bypass: str) -> None:
        ok, _ = check_target_in_scope(bypass, ["https://app.example.com"])
        assert not ok, f"{bypass} lẽ ra phải bị chặn"

    def test_ssrf_style_internal_ip_blocked(self) -> None:
        ok, _ = check_target_in_scope(
            "http://169.254.169.254/latest/meta-data/", ["https://app.example.com"]
        )
        assert not ok, "Địa chỉ metadata cloud không được nằm ngoài phạm vi"

    def test_localhost_blocked_when_scope_is_remote(self) -> None:
        ok, _ = check_target_in_scope("http://127.0.0.1:8080/admin", ["https://app.example.com"])
        assert not ok

    def test_dns_rebinding_style_blocked(self) -> None:
        # Dùng IP trực tiếp để vòng qua kiểm tra tên miền.
        ok, _ = check_target_in_scope("http://10.0.0.5/", ["https://app.example.com"])
        assert not ok
