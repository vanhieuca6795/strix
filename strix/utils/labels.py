"""Nhãn hiển thị đa ngữ cho phần giao diện bằng Python.

Strix hardcode toàn bộ chuỗi tiếng Anh. Module này cho phép hiển thị tiếng Việt
có dấu khi đặt ``STRIX_LANG=vi``, mà không phải sửa rải rác từng chuỗi.

Phạm vi áp dụng — có chủ đích:

- **Nhãn giao diện và báo cáo** (tiêu đề mục, tên trường): dịch.
- **Định danh máy đọc**: khoá JSON, header CSV, mã SARIF, tên severity gốc:
  **KHÔNG dịch**. Chúng chảy vào công cụ bên ngoài (CI, dashboard, parser
  SARIF); đổi chúng là phá tích hợp, không phải bản địa hoá.

Nội dung do agent sinh (mô tả, phân tích, PoC) không đi qua đây — nội dung đó
do model viết, và skill/tiếng Việt trong prompt mới là chỗ điều khiển nó.
"""

from __future__ import annotations

import os
from typing import Final


DEFAULT_LANGUAGE: Final[str] = "en"
SUPPORTED_LANGUAGES: Final[frozenset[str]] = frozenset({"en", "vi"})

#: Nhãn dùng chung giữa giao diện và báo cáo.
_LABELS: Final[dict[str, dict[str, str]]] = {
    # --- Báo cáo lỗ hổng (vulnerabilities/<id>.md) ---
    "report.title": {"en": "Security Penetration Test Report", "vi": "Báo cáo Kiểm thử Bảo mật"},
    "report.generated": {"en": "Generated", "vi": "Tạo lúc"},
    "report.summary": {"en": "Penetration test summary", "vi": "Tóm tắt kiểm thử xâm nhập"},
    "vuln.untitled": {"en": "Untitled Vulnerability", "vi": "Lỗ hổng chưa đặt tên"},
    "vuln.id": {"en": "ID", "vi": "Mã"},
    "vuln.severity": {"en": "Severity", "vi": "Mức độ"},
    "vuln.found": {"en": "Found", "vi": "Phát hiện lúc"},
    "vuln.target": {"en": "Target", "vi": "Mục tiêu"},
    "vuln.package": {"en": "Package", "vi": "Gói"},
    "vuln.ecosystem": {"en": "Ecosystem", "vi": "Hệ sinh thái"},
    "vuln.installed_version": {"en": "Installed Version", "vi": "Phiên bản đang cài"},
    "vuln.fixed_version": {"en": "Fixed Version", "vi": "Phiên bản đã vá"},
    "vuln.introduced_by": {"en": "Introduced By", "vi": "Đưa vào bởi"},
    "vuln.dependency_chain": {"en": "Dependency Chain", "vi": "Chuỗi phụ thuộc"},
    "vuln.endpoint": {"en": "Endpoint", "vi": "Điểm cuối"},
    "vuln.method": {"en": "Method", "vi": "Phương thức"},
    "vuln.cve": {"en": "CVE", "vi": "CVE"},
    "vuln.cwe": {"en": "CWE", "vi": "CWE"},
    "vuln.cvss": {"en": "CVSS", "vi": "CVSS"},
    "vuln.advisory_cvss": {"en": "Advisory CVSS", "vi": "CVSS theo khuyến cáo"},
    "vuln.contextual_cvss_vector": {
        "en": "Contextual CVSS Vector",
        "vi": "Vector CVSS theo ngữ cảnh",
    },
    "vuln.confidence": {"en": "Confidence", "vi": "Độ tin cậy"},
    "vuln.fix_effort": {"en": "Fix Effort", "vi": "Công sức khắc phục"},

    # --- Mục nội dung báo cáo ---
    "section.description": {"en": "Description", "vi": "Mô tả"},
    "section.evidence": {"en": "Evidence", "vi": "Bằng chứng"},
    "section.impact": {"en": "Impact", "vi": "Tác động"},
    "section.counterevidence": {"en": "Counterevidence", "vi": "Chứng cứ phản bác"},
    "section.confidence_rationale": {"en": "Confidence Rationale", "vi": "Cơ sở độ tin cậy"},
    "section.severity_change_conditions": {
        "en": "What Would Change This Severity",
        "vi": "Điều kiện làm thay đổi mức độ này",
    },
    "section.technical_analysis": {"en": "Technical Analysis", "vi": "Phân tích kỹ thuật"},
    "section.contextual_cvss": {"en": "Contextual CVSS", "vi": "CVSS theo ngữ cảnh"},
    "section.poc": {"en": "Proof of Concept", "vi": "Chứng minh khái niệm"},
    "section.code_analysis": {"en": "Code Analysis", "vi": "Phân tích mã nguồn"},
    "section.remediation": {"en": "Remediation", "vi": "Khắc phục"},
    "section.fix_verification": {"en": "Fix Verification", "vi": "Kiểm chứng bản vá"},
    "section.assumptions": {"en": "Assumptions", "vi": "Giả định"},
    "section.update_history": {"en": "Update History", "vi": "Lịch sử cập nhật"},

    # --- Chi tiết trong báo cáo ---
    "detail.no_description": {"en": "No description provided.", "vi": "Không có mô tả."},
    "detail.location": {"en": "Location", "vi": "Vị trí"},
    "detail.suggested_fix": {"en": "Suggested Fix", "vi": "Đề xuất khắc phục"},
    "detail.dropped_superseded": {"en": "Dropped as superseded", "vi": "Bỏ vì đã bị thay thế"},
    "detail.previous_severity": {"en": "Previous severity", "vi": "Mức độ trước đó"},
    "detail.previous_cvss": {"en": "Previous CVSS", "vi": "CVSS trước đó"},
    "detail.previous_confidence": {"en": "Previous confidence", "vi": "Độ tin cậy trước đó"},
    "detail.reason": {"en": "Reason", "vi": "Lý do"},
    "detail.line": {"en": "line", "vi": "dòng"},
    "detail.lines": {"en": "lines", "vi": "dòng"},
    "detail.updated": {"en": "updated", "vi": "đã cập nhật"},
    "detail.an_agent": {"en": "an agent", "vi": "một agent"},

    # --- Giao diện dòng lệnh ---
    "ui.vulns_realtime": {
        "en": "Vulnerabilities will be displayed in real-time.",
        "vi": "Lỗ hổng sẽ hiển thị theo thời gian thực.",
    },
    "ui.error_during_test": {
        "en": "Error during penetration test",
        "vi": "Lỗi trong quá trình kiểm thử xâm nhập",
    },
    "ui.completed": {"en": "Penetration test completed", "vi": "Kiểm thử xâm nhập hoàn tất"},
    "ui.vulnerabilities": {"en": "Vulnerabilities", "vi": "Lỗ hổng"},
    "ui.no_exploitable": {
        "en": "No exploitable vulnerabilities detected",
        "vi": "Không phát hiện lỗ hổng khai thác được",
    },
    "ui.input_tokens": {"en": "Input Tokens", "vi": "Token vào"},
    "ui.cached_tokens": {"en": "Cached Tokens", "vi": "Token đệm"},
    "ui.output_tokens": {"en": "Output Tokens", "vi": "Token ra"},
    "ui.cost": {"en": "Cost", "vi": "Chi phí"},
    "ui.output": {"en": "Output", "vi": "Kết quả"},
    "ui.target": {"en": "Target", "vi": "Mục tiêu"},
    "ui.results": {"en": "Results", "vi": "Thư mục kết quả"},
    "ui.view": {"en": "View", "vi": "Xem"},

    "ui.initiated": {"en": "Penetration test initiated", "vi": "Bắt đầu kiểm thử xâm nhập"},
    "ui.report": {"en": "Vulnerability Report", "vi": "Báo cáo lỗ hổng"},
    "ui.title": {"en": "Title", "vi": "Tiêu đề"},
    "ui.targets_count": {"en": "targets", "vi": "mục tiêu"},
    "ui.cvss_score": {"en": "CVSS Score", "vi": "Điểm CVSS"},
    "ui.summary": {"en": "Summary", "vi": "Tóm tắt"},
    # --- Mức độ nghiêm trọng (hiển thị; khoá máy vẫn là tiếng Anh) ---
    "severity.critical": {"en": "CRITICAL", "vi": "NGHIÊM TRỌNG"},
    "severity.high": {"en": "HIGH", "vi": "CAO"},
    "severity.medium": {"en": "MEDIUM", "vi": "TRUNG BÌNH"},
    "severity.low": {"en": "LOW", "vi": "THẤP"},
    "severity.info": {"en": "INFO", "vi": "THÔNG TIN"},
}

#: Mức độ nghiêm trọng dạng thường, dùng cho nhãn trong báo cáo.
_SEVERITY_TITLE: Final[dict[str, str]] = {
    "critical": "severity.critical",
    "high": "severity.high",
    "medium": "severity.medium",
    "low": "severity.low",
    "info": "severity.info",
}

_active_language: str | None = None


def resolve_language() -> str:
    """Ngôn ngữ hiện hành, đọc từ ``STRIX_LANG`` (mặc định ``en``)."""
    raw = (os.environ.get("STRIX_LANG") or "").strip().casefold()
    # Chấp nhận 'vi', 'vi-VN', 'vi_VN'.
    base = raw.replace("_", "-").split("-", 1)[0]
    return base if base in SUPPORTED_LANGUAGES else DEFAULT_LANGUAGE


def set_language(language: str | None) -> None:
    """Ghim ngôn ngữ (dùng cho test); ``None`` để đọc lại từ môi trường."""
    global _active_language  # noqa: PLW0603
    _active_language = language


def current_language() -> str:
    return _active_language if _active_language is not None else resolve_language()


def t(key: str, **kwargs: object) -> str:
    """Dịch ``key`` sang ngôn ngữ hiện hành.

    Thiếu bản dịch thì rơi về tiếng Anh, rồi tới chính ``key`` — không bao giờ
    ném lỗi, vì một nhãn thiếu không đáng làm hỏng cả báo cáo.
    """
    entry = _LABELS.get(key)
    if entry is None:
        return key
    language = current_language()
    text = entry.get(language) or entry.get(DEFAULT_LANGUAGE) or key
    return text.format(**kwargs) if kwargs else text


def severity_label(severity: str) -> str:
    """Nhãn hiển thị cho mức độ nghiêm trọng.

    ``severity`` đầu vào là khoá chuẩn (``critical``/``high``/…) để SARIF, CSV
    và so sánh vẫn đúng; chỉ phần hiển thị được dịch.
    """
    key = _SEVERITY_TITLE.get(severity.strip().casefold())
    if key is None:
        return severity.upper()
    return t(key)


def is_vietnamese() -> bool:
    return current_language() == "vi"
