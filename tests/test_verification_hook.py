"""Test tích hợp: cảnh báo kiểm chứng trong create_vulnerability_report.

Chứng minh rằng một phát hiện có PoC chạy thất bại sẽ được gắn cảnh báo, còn
phát hiện chưa từng kiểm chứng thì không bị làm phiền.
"""

from __future__ import annotations

import pytest

from strix.tools.reporting.tool import _verification_status
from strix.tools.verify import tool as verify
from strix.tools.verify.tool import VerificationRecord, reset_ledger


@pytest.fixture(autouse=True)
def _clean() -> None:
    reset_ledger()
    yield
    reset_ledger()


def _record(
    *,
    key: str,
    ran: bool = True,
    expectation: str = "",
    met: bool = False,
    error: str | None = None,
) -> VerificationRecord:
    record = VerificationRecord(
        verification_id="v1",
        finding_key=key,
        language="bash",
        exit_code=0 if ran else 124,
        duration_s=1.0,
        output="output",
        expectation=expectation,
        expectation_met=met,
        ran=ran,
        error=error,
    )
    verify._LEDGER[key] = record
    return record


class TestNoWarningWhenClean:
    def test_no_ledger_means_no_warning(self) -> None:
        # Scan whitebox thuần đọc source: không chạy PoC, không nên cảnh báo.
        assert _verification_status(finding_key="sqli", title="sqli") is None

    def test_untested_finding_not_flagged(self) -> None:
        _record(key="other-finding", expectation="x", met=True)
        # Phát hiện này chưa từng kiểm chứng -> không có gì để cảnh báo.
        assert _verification_status(finding_key="sqli", title="sqli") is None

    def test_successful_verification_not_flagged(self) -> None:
        _record(key="rce /ping", expectation="uid=0", met=True)
        assert _verification_status(finding_key="rce /ping", title="rce /ping") is None


class TestWarningOnFailure:
    def test_expectation_not_met_warns(self) -> None:
        _record(key="rce /ping", expectation="uid=0", met=False)
        warning = _verification_status(finding_key="rce /ping", title="rce /ping")

        assert warning is not None
        assert warning["ran"] is True
        assert warning["expectation"] == "uid=0"
        assert "KHÔNG chứa" in warning["warning"]
        assert "confidence" in warning["warning"]

    def test_poc_not_running_warns(self) -> None:
        _record(key="sqli", ran=False, error="container died")
        warning = _verification_status(finding_key="sqli", title="sqli")

        assert warning is not None
        assert warning["ran"] is False
        assert "KHÔNG chạy được" in warning["warning"]
        assert "assumptions" in warning["warning"]

    def test_no_expectation_set_is_not_flagged(self) -> None:
        # Chạy được nhưng không đặt kỳ vọng: chưa đủ căn cứ để nói thất bại.
        _record(key="probe", expectation="", met=False)
        assert _verification_status(finding_key="probe", title="probe") is None


class TestLooseTitleMatching:
    """Khớp lỏng chỉ hoạt động khi hai chuỗi có PHẦN CHUNG thật.

    Đây là giới hạn có chủ đích: khớp theo chuỗi con không thể suy ra ngữ nghĩa
    ("RCE" và "Command injection" là hai từ khác nhau dù cùng nghĩa). Vì vậy
    agent nên dùng khoá ổn định và tái sử dụng nó; khớp lỏng chỉ là lưới an
    toàn cho trường hợp lệch nhẹ.
    """

    def test_matches_when_key_is_substring_of_title(self) -> None:
        _record(key="qua tham số host", expectation="uid=0", met=False)
        warning = _verification_status(
            finding_key="", title="Command injection tại /ping qua tham số host"
        )
        assert warning is not None

    def test_unrelated_words_do_not_match(self) -> None:
        # "RCE" không phải chuỗi con của "Command injection": đúng như thiết kế,
        # không khớp. Agent phải dùng khoá ổn định để việc tra cứu chắc chắn.
        _record(key="RCE", expectation="uid=0", met=False)
        assert _verification_status(finding_key="", title="Command injection") is None

    def test_no_false_match_for_unrelated_title(self) -> None:
        _record(key="rce /ping", expectation="uid=0", met=False)
        assert _verification_status(finding_key="", title="SQL injection /user") is None


class TestWarningHelpsTheRightPerson:
    """Cảnh báo phải nói được điều chủ hệ thống cần nghe."""

    def test_warning_mentions_the_missing_marker(self) -> None:
        _record(key="rce", expectation="root:x:0:0", met=False)
        warning = _verification_status(finding_key="rce", title="rce")
        assert warning is not None
        # Phải nêu chính xác dấu hiệu nào chưa thấy, để người đọc tự đánh giá.
        assert "root:x:0:0" in warning["warning"]
