"""Test cho cổng `needs_follow_up` và skill attack_chaining.

Bảo đảm cốt lõi: một cuộc quét KHÔNG THỂ kết thúc khi còn bề mặt chưa giải
quyết mà không có quyết định có ý thức của agent.
"""

from __future__ import annotations

import json

import pytest

from strix.agents.prompt import render_system_prompt
from strix.skills import load_skills
from strix.tools.coverage import tools as coverage
from strix.tools.finish.tool import _unresolved_gate, finish_scan


class _FakeCtx:
    """RunContextWrapper tối thiểu để gọi tool."""

    class _RunConfig:
        trace_include_sensitive_data = True

    class _Coordinator:
        reserve_stopped = False

        async def active_agents_except(self, _me: object) -> list[object]:
            return []

        async def snapshot(self) -> dict:
            return {}

        async def set_status(self, *_a: object, **_k: object) -> None:
            return None

    def __init__(self) -> None:
        self.context = {"agent_id": "root-1", "parent_id": None, "coordinator": self._Coordinator()}
        self.run_config = self._RunConfig()
        self.tool_name = "finish_scan"
        self.tool_call_id = "call-1"


@pytest.fixture(autouse=True)
def _clean_coverage() -> None:
    coverage._coverage_storage.clear()
    yield
    coverage._coverage_storage.clear()


def _add_coverage(surface: str, outcome: str) -> None:
    coverage._record_impl(
        surface=surface,
        risk_area="test risk",
        outcome=outcome,
        evidence="bằng chứng kiểm thử",
        agent_id="root-1",
        agent_name="Root Agent",
    )


class TestGateBlocksFirstCall:
    def test_no_gate_when_nothing_unresolved(self) -> None:
        _add_coverage("POST /login", "no_issue_found")
        assert _unresolved_gate(acknowledged=False) is None

    def test_no_gate_when_no_coverage_at_all(self) -> None:
        # Quét whitebox thuần đọc source có thể không ghi coverage nào.
        assert _unresolved_gate(acknowledged=False) is None

    def test_gate_fires_on_needs_follow_up(self) -> None:
        _add_coverage("GET /admin", "needs_follow_up")
        gate = _unresolved_gate(acknowledged=False)

        assert gate is not None
        assert gate["success"] is False
        assert gate["scan_completed"] is False
        assert "needs_follow_up" in gate["error"]

    def test_gate_lists_the_open_surfaces(self) -> None:
        _add_coverage("GET /admin", "needs_follow_up")
        _add_coverage("POST /upload", "needs_follow_up")
        gate = _unresolved_gate(acknowledged=False)

        assert gate is not None
        surfaces = [s["surface"] for s in gate["unresolved_surfaces"]]
        assert "GET /admin" in surfaces
        assert "POST /upload" in surfaces
        assert len(surfaces) == 2

    def test_gate_carries_evidence_for_review(self) -> None:
        _add_coverage("GET /admin", "needs_follow_up")
        gate = _unresolved_gate(acknowledged=False)
        assert gate is not None
        # Phải kèm lý do tồn đọng để agent tự đánh giá lại được.
        assert gate["unresolved_surfaces"][0]["evidence"]

    def test_gate_offers_both_ways_forward(self) -> None:
        _add_coverage("GET /admin", "needs_follow_up")
        gate = _unresolved_gate(acknowledged=False)
        assert gate is not None
        # Phải nói rõ cả hai lựa chọn, kèm nghĩa vụ báo cáo.
        assert "resolve it now" in gate["next_step"]
        assert "unresolved_acknowledged=True" in gate["next_step"]
        assert "recommendations" in gate["next_step"]


class TestAcknowledgedPassesThrough:
    def test_acknowledged_bypasses_gate(self) -> None:
        _add_coverage("GET /admin", "needs_follow_up")
        assert _unresolved_gate(acknowledged=True) is None

    def test_other_outcomes_never_gate(self) -> None:
        _add_coverage("GET /a", "no_issue_found")
        _add_coverage("GET /b", "ruled_out")
        _add_coverage("GET /c", "not_applicable")
        _add_coverage("GET /d", "reported")
        assert _unresolved_gate(acknowledged=False) is None


class TestGateInsideFinishScan:
    """Cổng phải chặn ở đúng tầng tool, không chỉ ở hàm phụ trợ."""

    @pytest.mark.asyncio
    async def test_first_call_is_rejected(self) -> None:
        _add_coverage("GET /admin", "needs_follow_up")
        ctx = _FakeCtx()

        raw = await finish_scan.on_invoke_tool(
            ctx,
            json.dumps({
                "executive_summary": "Tóm tắt",
                "methodology": "Phương pháp",
                "technical_analysis": "Phân tích",
                "recommendations": "Khuyến nghị",
            }),
        )
        payload = json.loads(raw)

        assert payload["success"] is False
        assert payload["scan_completed"] is False

    @pytest.mark.asyncio
    async def test_second_call_with_acknowledgement_proceeds(self) -> None:
        _add_coverage("GET /admin", "needs_follow_up")
        ctx = _FakeCtx()

        raw = await finish_scan.on_invoke_tool(
            ctx,
            json.dumps({
                "executive_summary": "Tóm tắt",
                "methodology": "Phương pháp",
                "technical_analysis": "Phân tích",
                "recommendations": "GET /admin vẫn chưa kiểm thử được.",
                "unresolved_acknowledged": True,
            }),
        )
        payload = json.loads(raw)

        # Qua cổng; có thể vẫn lỗi vì thiếu report state, nhưng KHÔNG được
        # còn bị chặn vì needs_follow_up.
        assert "needs_follow_up" not in str(payload.get("error", ""))

    @pytest.mark.asyncio
    async def test_clean_scan_not_blocked(self) -> None:
        _add_coverage("GET /", "no_issue_found")
        ctx = _FakeCtx()

        raw = await finish_scan.on_invoke_tool(
            ctx,
            json.dumps({
                "executive_summary": "Tóm tắt",
                "methodology": "Phương pháp",
                "technical_analysis": "Phân tích",
                "recommendations": "Không có gì tồn đọng.",
            }),
        )
        payload = json.loads(raw)

        assert "needs_follow_up" not in str(payload.get("error", ""))


class TestChainigSkillWired:
    def test_skill_loads(self) -> None:
        loaded = load_skills(["analysis/attack_chaining"])
        assert "attack_chaining" in loaded
        body = loaded["attack_chaining"]
        assert len(body) > 1_000

    def test_skill_is_in_every_agent_prompt(self) -> None:
        prompt = render_system_prompt(scan_mode="standard", is_root=True)
        assert "Attack Chaining" in prompt

    def test_skill_teaches_the_verification_discipline(self) -> None:

        body = load_skills(["analysis/attack_chaining"])["attack_chaining"]
        # Skill phải buộc kiểm chứng mối nối, không chỉ gợi ý ý tưởng.
        assert "verify_poc" in body
        assert "marker" in body.lower()
        # Và phải nói cả trường hợp KHÔNG ghép được - đó cũng là kết quả thật.
        assert "does not combine" in body.lower() or "do not have a chain" in body.lower()


class TestFinishGateInPrompt:
    def test_root_prompt_documents_gate(self) -> None:

        prompt = render_system_prompt(scan_mode="standard", is_root=True)
        assert "<finish_gate>" in prompt
        assert "unresolved_acknowledged" in prompt

    def test_child_prompt_has_no_gate(self) -> None:

        prompt = render_system_prompt(scan_mode="standard", is_root=False)
        # Subagent không gọi finish_scan, nên không cần khối này.
        assert "<finish_gate>" not in prompt
