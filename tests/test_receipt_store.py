"""Test cho module receipt_store."""

from __future__ import annotations

import pytest

from strix.utils import receipt_store
from strix.utils.evidence_grounding import verify_evidence_candidates


@pytest.fixture(autouse=True)
def _clean_store() -> None:
    receipt_store.reset_receipts()
    yield
    receipt_store.reset_receipts()


class TestRecordReceipt:
    def test_records_string_result(self) -> None:
        receipt_store.record_receipt("agent-1", "exec_command", "22/tcp open ssh\n")
        assert receipt_store.receipts_for("agent-1") == ["22/tcp open ssh\n"]

    def test_ignores_non_string_result(self) -> None:
        receipt_store.record_receipt("agent-1", "exec_command", {"ok": True})
        receipt_store.record_receipt("agent-1", "exec_command", None)
        assert receipt_store.receipts_for("agent-1") == []

    def test_ignores_blank_result(self) -> None:
        receipt_store.record_receipt("agent-1", "exec_command", "   \n  ")
        assert receipt_store.receipts_for("agent-1") == []

    @pytest.mark.parametrize(
        "internal_tool",
        ["think", "create_todo", "load_skill", "create_vulnerability_report", "list_reports"],
    )
    def test_ignores_internal_tools(self, internal_tool: str) -> None:
        receipt_store.record_receipt("agent-1", internal_tool, "some output that looks real")
        assert receipt_store.receipts_for("agent-1") == []

    def test_records_exec_and_web_tools(self) -> None:
        receipt_store.record_receipt("agent-1", "exec_command", "output A")
        receipt_store.record_receipt("agent-1", "web_get_contents", "output B")
        receipt_store.record_receipt("agent-1", "repeat_request", "output C")
        assert len(receipt_store.receipts_for("agent-1")) == 3


class TestAgentIsolation:
    def test_receipts_are_per_agent(self) -> None:
        receipt_store.record_receipt("agent-1", "exec_command", "agent one output")
        receipt_store.record_receipt("agent-2", "exec_command", "agent two output")
        assert receipt_store.receipts_for("agent-1") == ["agent one output"]
        assert receipt_store.receipts_for("agent-2") == ["agent two output"]

    def test_unknown_agent_has_no_receipts(self) -> None:
        assert receipt_store.receipts_for("never-seen") == []

    def test_none_agent_id_bucketed_separately(self) -> None:
        receipt_store.record_receipt(None, "exec_command", "orphan output")
        assert receipt_store.receipts_for(None) == ["orphan output"]
        assert receipt_store.receipts_for("agent-1") == []


class TestBounds:
    def test_per_agent_bound_enforced(self) -> None:
        for i in range(receipt_store._MAX_RECEIPTS_PER_AGENT + 50):
            receipt_store.record_receipt("agent-1", "exec_command", f"output {i}")
        receipts = receipt_store.receipts_for("agent-1")
        assert len(receipts) == receipt_store._MAX_RECEIPTS_PER_AGENT
        # Cửa sổ trượt: giữ cái mới nhất, bỏ cái cũ nhất.
        assert receipts[-1] == f"output {receipt_store._MAX_RECEIPTS_PER_AGENT + 49}"
        assert "output 0" not in receipts

    def test_oversized_receipt_truncated(self) -> None:
        big = "A" * (receipt_store._MAX_RECEIPT_CHARS * 2) + "END_MARKER"
        receipt_store.record_receipt("agent-1", "exec_command", big)
        stored = receipt_store.receipts_for("agent-1")[0]
        assert len(stored) < len(big)
        # Giữ đuôi để không mất mã thoát / dòng lỗi.
        assert stored.endswith("END_MARKER")

    def test_agent_tracking_bound(self) -> None:
        for i in range(receipt_store._MAX_TRACKED_AGENTS + 20):
            receipt_store.record_receipt(f"agent-{i}", "exec_command", "x")
        assert len(receipt_store.receipt_stats()) <= receipt_store._MAX_TRACKED_AGENTS


class TestReceiptsForVerification:
    def test_prefers_own_receipts(self) -> None:
        receipt_store.record_receipt("agent-1", "exec_command", "own")
        receipt_store.record_receipt("agent-2", "exec_command", "other")
        assert receipt_store.receipts_for_verification("agent-1") == ["own"]

    def test_falls_back_to_all_when_agent_has_none(self) -> None:
        receipt_store.record_receipt("agent-1", "exec_command", "from agent one")
        result = receipt_store.receipts_for_verification("root-agent")
        assert result == ["from agent one"]

    def test_no_receipts_at_all_returns_empty(self) -> None:
        assert receipt_store.receipts_for_verification("agent-1") == []


class TestResetAndStats:
    def test_reset_clears_everything(self) -> None:
        receipt_store.record_receipt("agent-1", "exec_command", "x")
        receipt_store.reset_receipts()
        assert receipt_store.receipt_stats() == {}

    def test_stats_reports_counts(self) -> None:
        receipt_store.record_receipt("agent-1", "exec_command", "a")
        receipt_store.record_receipt("agent-1", "exec_command", "b")
        receipt_store.record_receipt("agent-2", "exec_command", "c")
        assert receipt_store.receipt_stats() == {"agent-1": 2, "agent-2": 1}


class TestIntegrationWithGrounding:
    """Chuỗi hoàn chỉnh: tool chạy -> receipt -> kiểm chứng bằng chứng."""

    def test_real_output_verifies_fabricated_does_not(self) -> None:
        nmap_output = (
            "$ nmap -sV 10.10.11.234\n"
            "PORT   STATE SERVICE VERSION\n"
            "22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5\n"
            "80/tcp open  http    nginx 1.18.0\n"
        )
        receipt_store.record_receipt("agent-1", "exec_command", nmap_output)
        receipts = receipt_store.receipts_for_verification("agent-1")

        honest = "Kết quả:\n```\n22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5\n```"
        assert verify_evidence_candidates(honest, receipts).verified

        fabricated = (
            "Kết quả:\n```\n"
            "3306/tcp open  mysql   MySQL 5.7.38\n"
            "6379/tcp open  redis   Redis 6.2.7\n"
            "```"
        )
        assert not verify_evidence_candidates(fabricated, receipts).verified
