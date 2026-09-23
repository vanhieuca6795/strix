"""Test tích hợp: chứng minh chuỗi ghi receipt -> kiểm chứng bằng chứng hoạt động thật.

Test này chạy qua đúng các hàm mà Strix gọi khi agent thực thi tool và khi
agent nộp báo cáo lỗ hổng — không phải mock.
"""

from __future__ import annotations

import json

import pytest

from strix.agents.factory import _agent_id_from_ctx, _record_tool_receipt
from strix.config import loader as config_loader
from strix.tools.reporting.tool import _verify_evidence_grounding
from strix.utils import receipt_store


@pytest.fixture(autouse=True)
def _clean_store() -> None:
    receipt_store.reset_receipts()
    yield
    receipt_store.reset_receipts()


class _FakeCtx:
    """Bắt chước RunContextWrapper mà SDK truyền vào tool."""

    def __init__(self, agent_id: str | None) -> None:
        self.context = {"agent_id": agent_id} if agent_id else {}


NMAP_REAL_OUTPUT = """$ nmap -sV 10.10.11.234
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 10.10.11.234
Host is up (0.021s latency).
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
80/tcp open  http    nginx 1.18.0
Nmap done: 1 IP address (1 host up) scanned in 12.34 seconds
"""


class TestAgentIdExtraction:
    def test_extracts_agent_id(self) -> None:
        assert _agent_id_from_ctx(_FakeCtx("agent-abc")) == "agent-abc"

    def test_missing_agent_id_returns_none(self) -> None:
        assert _agent_id_from_ctx(_FakeCtx(None)) is None

    def test_ctx_without_context_attr(self) -> None:
        assert _agent_id_from_ctx(object()) is None


class TestReceiptRecordingThroughFactory:
    """Factory ghi receipt đúng cách khi tool trả kết quả."""

    def test_exec_command_output_becomes_receipt(self) -> None:
        ctx = _FakeCtx("agent-1")
        _record_tool_receipt(ctx, "exec_command", NMAP_REAL_OUTPUT)
        assert receipt_store.receipts_for("agent-1") == [NMAP_REAL_OUTPUT]

    def test_internal_tool_not_recorded(self) -> None:
        ctx = _FakeCtx("agent-1")
        _record_tool_receipt(ctx, "think", "suy nghĩ nội bộ, không phải bằng chứng")
        assert receipt_store.receipts_for("agent-1") == []

    def test_recording_failure_never_raises(self) -> None:
        # Receipt là phụ trợ: kể cả result dị thường cũng không được làm hỏng tool.
        ctx = _FakeCtx("agent-1")
        _record_tool_receipt(ctx, "exec_command", None)
        _record_tool_receipt(ctx, "exec_command", {"not": "a string"})
        _record_tool_receipt(ctx, "exec_command", 12345)
        assert receipt_store.receipts_for("agent-1") == []


class TestVerifyEvidenceGroundingEndToEnd:
    """Chuỗi đầy đủ: tool chạy -> receipt -> agent nộp báo cáo."""

    def test_honest_evidence_passes(self) -> None:
        ctx = _FakeCtx("agent-1")
        _record_tool_receipt(ctx, "exec_command", NMAP_REAL_OUTPUT)

        honest = (
            "Quét cổng phát hiện SSH lộ ra ngoài:\n"
            "```\n22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5\n```"
        )
        result = _verify_evidence_grounding(evidence=honest, agent_id="agent-1")
        assert result is None, "Bằng chứng thật phải được cho qua"

    def test_fabricated_evidence_rejected(self) -> None:
        ctx = _FakeCtx("agent-1")
        _record_tool_receipt(ctx, "exec_command", NMAP_REAL_OUTPUT)

        fabricated = (
            "Phát hiện MySQL và Redis lộ ra Internet:\n"
            "```\n"
            "3306/tcp open  mysql   MySQL 5.7.38\n"
            "6379/tcp open  redis   Redis key-value store 6.2.7\n"
            "```"
        )
        result = _verify_evidence_grounding(evidence=fabricated, agent_id="agent-1")
        assert result is not None, "Bằng chứng bịa PHẢI bị từ chối"
        assert result["success"] is False
        assert "verif" in result["error"].lower()
        assert len(result["errors"]) >= 2
        assert "STRIX_EVIDENCE_GROUNDING" in result["hint"]

    def test_agent_cannot_borrow_another_agents_receipts(self) -> None:
        # agent-1 chạy nmap; agent-2 chưa chạy gì nhưng muốn nộp báo cáo.
        # agent-2 không có receipt riêng -> fallback toàn run (chấp nhận được,
        # vì root agent tổng hợp). Nhưng nếu agent-2 CÓ receipt riêng thì chỉ
        # được dùng receipt của chính nó.
        ctx1 = _FakeCtx("agent-1")
        _record_tool_receipt(ctx1, "exec_command", NMAP_REAL_OUTPUT)

        ctx2 = _FakeCtx("agent-2")
        _record_tool_receipt(ctx2, "exec_command", "$ whoami\nwww-data\n")

        # agent-2 tự bịa thông tin từ output của agent-1 -> phải bị chặn.
        borrowed = "```\n80/tcp open  http    nginx 1.18.0\n```"
        result = _verify_evidence_grounding(evidence=borrowed, agent_id="agent-2")
        assert result is not None, "agent-2 không được mượn output của agent-1"
        assert result["success"] is False

    def test_no_receipts_allows_report_through(self) -> None:
        # Scan whitebox thuần đọc source: không chạy lệnh nào -> không có
        # receipt -> không được chặn oan.
        result = _verify_evidence_grounding(
            evidence="Đọc source thấy hàm eval() ở dòng 42 của app.py.",
            agent_id="agent-does-not-exist",
        )
        assert result is None

    def test_grounding_can_be_disabled_by_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("STRIX_EVIDENCE_GROUNDING", "false")
        # load_settings() được memoize nên phải xoá cache để env mới có hiệu lực.
        monkeypatch.setattr(config_loader, "_cached", None)

        ctx = _FakeCtx("agent-1")
        _record_tool_receipt(ctx, "exec_command", NMAP_REAL_OUTPUT)

        fabricated = "```\n9999/tcp open  totally-made-up\n```"
        result = _verify_evidence_grounding(evidence=fabricated, agent_id="agent-1")
        assert result is None, "Khi tắt kiểm chứng thì không được chặn"


class TestReportPayloadIsValidJson:
    """Cấu trúc lỗi trả về phải là JSON hợp lệ mà SDK có thể chuyển cho model."""

    def test_rejection_is_json_serializable(self) -> None:
        ctx = _FakeCtx("agent-1")
        _record_tool_receipt(ctx, "exec_command", NMAP_REAL_OUTPUT)
        result = _verify_evidence_grounding(
            evidence="```\n1337/tcp open  fake-service\n```", agent_id="agent-1"
        )
        assert result is not None
        encoded = json.dumps(result, ensure_ascii=False)
        assert "bằng chứng" in encoded.lower() or "evidence" in encoded.lower()
        # Tiếng Việt phải giữ nguyên dấu, không bị escape.
        assert "\\u" not in encoded or "không khớp" in encoded
