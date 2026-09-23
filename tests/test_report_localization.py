"""Test tích hợp: báo cáo và giao diện thật sự ra tiếng Việt.

Kiểm chứng qua đúng các hàm render mà Strix dùng, không phải mock.
"""

from __future__ import annotations

import csv
import json

import pytest

from strix.report.writer import (
    render_vulnerability_md,
    write_executive_report,
    write_vulnerabilities,
)
from strix.utils.labels import set_language


@pytest.fixture(autouse=True)
def _reset() -> None:
    set_language(None)
    yield
    set_language(None)


REPORT = {
    "title": "SQL Injection tại /api/users",
    "id": "vuln-0001",
    "severity": "high",
    "timestamp": "2026-09-23 10:00:00 UTC",
    "target": "https://app.example.com",
    "endpoint": "/api/users",
    "method": "GET",
    "cve": "CVE-2024-12345",
    "cwe": "CWE-89",
    "cvss": 8.1,
    "confidence": "high",
    "description": "Tham số id không được kiểm tra.",
    "impact": "Đọc toàn bộ cơ sở dữ liệu.",
    "evidence": "GET /api/users?id=1' OR '1'='1 -> 200 OK",
    "technical_analysis": "Ứng dụng nối chuỗi trực tiếp.",
    "poc_description": "Payload:",
    "poc_script_code": "```bash\ncurl 'https://app.example.com/api/users'\n```",
    "remediation_steps": "Dùng truy vấn tham số hoá.",
    "assumptions": "Không cần xác thực.",
}


class TestReportRendersVietnamese:
    def test_section_headings_in_vietnamese(self) -> None:
        set_language("vi")
        md = render_vulnerability_md(REPORT)
        for expected in (
            "## Mô tả",
            "## Bằng chứng",
            "## Tác động",
            "## Phân tích kỹ thuật",
            "## Chứng minh khái niệm",
            "## Khắc phục",
            "## Giả định",
        ):
            assert expected in md, f"thiếu mục: {expected}"

    def test_field_labels_in_vietnamese(self) -> None:
        set_language("vi")
        md = render_vulnerability_md(REPORT)
        for expected in (
            "**Mã:**",
            "**Mức độ:**",
            "**Phát hiện lúc:**",
            "**Mục tiêu:**",
            "**Điểm cuối:**",
            "**Độ tin cậy:**",
        ):
            assert expected in md, f"thiếu nhãn: {expected}"

    def test_severity_translated(self) -> None:
        set_language("vi")
        md = render_vulnerability_md(REPORT)
        assert "**Mức độ:** CAO" in md

    def test_english_still_default(self) -> None:
        md = render_vulnerability_md(REPORT)
        assert "## Description" in md
        assert "**Severity:** HIGH" in md
        assert "## Mô tả" not in md

    def test_diacritics_preserved_through_render(self) -> None:
        set_language("vi")
        md = render_vulnerability_md(REPORT)
        # Dấu phải còn nguyên sau khi render, không bị escape hay hỏng.
        assert "Bằng chứng" in md
        assert "\\u1eb1" not in md  # không bị escape thành \uXXXX

    def test_technical_identifiers_unchanged(self) -> None:
        set_language("vi")
        md = render_vulnerability_md(REPORT)
        # Định danh kỹ thuật phải giữ nguyên để tra cứu và tích hợp.
        assert "CVE-2024-12345" in md
        assert "CWE-89" in md
        assert "8.1" in md
        assert "/api/users" in md

    def test_code_fence_intact(self) -> None:
        set_language("vi")
        md = render_vulnerability_md(REPORT)
        assert "```bash" in md
        assert "curl 'https://app.example.com/api/users'" in md

    def test_update_history_heading_translated(self) -> None:
        set_language("vi")
        report = {
            **REPORT,
            "update_history": [
                {
                    "timestamp": "2026-09-23 11:00:00 UTC",
                    "agent_name": "Agent A",
                    "fields": ["severity"],
                    "reason": "Đã xác minh lại",
                }
            ],
        }
        md = render_vulnerability_md(report)
        assert "## Lịch sử cập nhật" in md

    def test_untitled_fallback_translated(self) -> None:
        set_language("vi")
        md = render_vulnerability_md({**REPORT, "title": ""})
        assert "Lỗ hổng chưa đặt tên" in md


class TestExecutiveReport:
    def test_title_translated(self, tmp_path) -> None:
        set_language("vi")
        write_executive_report(tmp_path, "Nội dung tóm tắt.")
        content = (tmp_path / "penetration_test_report.md").read_text(encoding="utf-8")
        assert "# Báo cáo Kiểm thử Bảo mật" in content
        assert "**Tạo lúc:**" in content
        # Nội dung agent sinh phải giữ nguyên văn.
        assert "Nội dung tóm tắt." in content

    def test_english_default(self, tmp_path) -> None:
        write_executive_report(tmp_path, "Summary body.")
        content = (tmp_path / "penetration_test_report.md").read_text(encoding="utf-8")
        assert "# Security Penetration Test Report" in content
        assert "**Generated:**" in content


class TestMachineReadableOutputUnchanged:
    """Đầu ra cho máy đọc không được đổi — đây là ràng buộc cốt lõi."""

    def test_csv_and_json_use_english_severity_keys(self, tmp_path) -> None:
        set_language("vi")
        reports = [{**REPORT, "file": "vulnerabilities/vuln-0001.md"}]
        write_vulnerabilities(tmp_path, reports, saved_vuln_ids=set())

        # CSV: header và giá trị severity phải là tiếng Anh chuẩn.
        with (tmp_path / "vulnerabilities.csv").open(encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        assert rows
        assert rows[0]["severity"] == "HIGH"
        assert set(rows[0].keys()) == {"id", "title", "severity", "timestamp", "file"}

        # JSON: khoá chuẩn, không dịch.
        data = json.loads((tmp_path / "vulnerabilities.json").read_text(encoding="utf-8"))
        assert data[0]["severity"] == "high"
        assert data[0]["id"] == "vuln-0001"

