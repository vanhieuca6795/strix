"""Test cho ``verify_poc``: chạy PoC thật và lấy output làm bằng chứng.

Trọng tâm: chứng minh rằng một PoC CHƯA TỪNG CHẠY không thể lọt qua như một
phát hiện đã xác nhận.
"""

from __future__ import annotations

import json

import pytest

from strix.tools.verify import tool as verify
from strix.tools.verify.tool import (
    VerificationRecord,
    ledger_snapshot,
    lookup_verification,
    reset_ledger,
    verify_poc,
)
from strix.utils import receipt_store


class _FakeExecResult:
    """Bắt chước ExecResult của SDK: stdout/stderr là bytes."""

    def __init__(self, stdout: bytes = b"", stderr: bytes = b"", exit_code: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code


class _FakeSession:
    """Sandbox giả: trả kết quả định sẵn, và ghi lại lệnh đã nhận."""

    def __init__(self, result: _FakeExecResult | Exception | None = None) -> None:
        self.result = result if result is not None else _FakeExecResult(b"ok\n")
        self.calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    async def exec(self, *command: object, **kwargs: object) -> _FakeExecResult:
        self.calls.append((command, kwargs))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result

    async def write(self, _path: object, _data: object, **_: object) -> None:
        return None


class _FakeCtx:
    """Bắt chước RunContextWrapper đủ để SDK gọi được tool.

    SDK đọc ``ctx.run_config.trace_include_sensitive_data`` trước khi chạy
    handler, nên fake phải có thuộc tính đó.
    """

    class _RunConfig:
        trace_include_sensitive_data = True

    def __init__(self, session: object | None, **extra: object) -> None:
        self.context: dict[str, object] = {"agent_id": "agent-1"}
        if session is not None:
            self.context["sandbox_session"] = session
        self.context.update(extra)
        self.run_config = self._RunConfig()
        # SDK đọc các thuộc tính này trước khi gọi handler.
        self.tool_name = "verify_poc"
        self.tool_call_id = "call-1"


@pytest.fixture(autouse=True)
def _clean() -> None:
    reset_ledger()
    verify._LAST_SCRIPT.clear()
    yield
    reset_ledger()
    verify._LAST_SCRIPT.clear()


def _payload(raw: str) -> dict:
    return json.loads(raw)


class TestRunsThePoc:
    @pytest.mark.asyncio
    async def test_reports_success_and_output(self) -> None:
        session = _FakeSession(_FakeExecResult(b"uid=0(root)\n", b"", 0))
        ctx = _FakeCtx(session)

        result = _payload(await verify_poc.on_invoke_tool(ctx, json.dumps({
            "script": "id",
            "expect": "uid=0(root)",
        })))

        assert result["success"] is True
        assert result["ran"] is True
        assert result["exit_code"] == 0
        assert result["expectation_met"] is True
        assert "uid=0(root)" in result["output"]

    @pytest.mark.asyncio
    async def test_captures_stderr_too(self) -> None:
        session = _FakeSession(_FakeExecResult(b"", b"Traceback: boom\n", 1))
        ctx = _FakeCtx(session)

        result = _payload(await verify_poc.on_invoke_tool(ctx, json.dumps({"script": "false"})))

        # stderr cũng là bằng chứng - phải được giữ.
        assert "boom" in result["output"]
        assert result["exit_code"] == 1

    @pytest.mark.asyncio
    async def test_passes_timeout_to_exec(self) -> None:
        session = _FakeSession()
        ctx = _FakeCtx(session)

        await verify_poc.on_invoke_tool(ctx, json.dumps({"script": "sleep 1", "timeout_s": 42}))

        _, kwargs = session.calls[0]
        assert kwargs.get("timeout") == 42

    @pytest.mark.asyncio
    async def test_python_language_uses_python3(self) -> None:
        session = _FakeSession()
        ctx = _FakeCtx(session)

        await verify_poc.on_invoke_tool(
            ctx, json.dumps({"script": "print(1)", "language": "python"})
        )

        command, _ = session.calls[0]
        assert command[0] == "python3"

    @pytest.mark.asyncio
    async def test_bash_language_uses_bash(self) -> None:
        session = _FakeSession()
        ctx = _FakeCtx(session)

        await verify_poc.on_invoke_tool(ctx, json.dumps({"script": "id"}))

        command, _ = session.calls[0]
        assert command[0] == "bash"


class TestDetectsFailedExpectation:
    """Đây là bảo đảm cốt lõi: PoC không đạt kỳ vọng phải bị nêu rõ."""

    @pytest.mark.asyncio
    async def test_expectation_not_met_is_flagged(self) -> None:
        session = _FakeSession(_FakeExecResult(b"403 Forbidden\n", b"", 0))
        ctx = _FakeCtx(session)

        result = _payload(
            await verify_poc.on_invoke_tool(
                ctx,
                json.dumps({"script": "curl -s target", "expect": "root:x:0:0"}),
            )
        )

        assert result["expectation_met"] is False
        assert "hint" in result
        assert "does not contain" in result["hint"]

    @pytest.mark.asyncio
    async def test_no_expectation_is_called_out(self) -> None:
        session = _FakeSession(_FakeExecResult(b"whatever\n", b"", 0))
        ctx = _FakeCtx(session)

        result = _payload(await verify_poc.on_invoke_tool(ctx, json.dumps({"script": "ls"})))

        # Không có `expect` thì không thể kết luận thành công.
        assert result["expectation_met"] is False
        assert "undetermined" in result["hint"]


class TestFailureHandling:
    @pytest.mark.asyncio
    async def test_exec_exception_returns_error_not_crash(self) -> None:
        session = _FakeSession(RuntimeError("container died"))
        ctx = _FakeCtx(session)

        result = _payload(await verify_poc.on_invoke_tool(ctx, json.dumps({"script": "id"})))

        assert result["success"] is False
        assert result["ran"] is False
        assert "container died" in result["error"]

    @pytest.mark.asyncio
    async def test_no_sandbox_session_is_reported(self) -> None:
        ctx = _FakeCtx(None)

        result = _payload(await verify_poc.on_invoke_tool(ctx, json.dumps({"script": "id"})))

        assert result["ran"] is False
        assert "No sandbox session" in result["error"]

    @pytest.mark.asyncio
    async def test_empty_script_rejected(self) -> None:
        ctx = _FakeCtx(_FakeSession())

        result = _payload(await verify_poc.on_invoke_tool(ctx, json.dumps({"script": "   "})))

        assert result["success"] is False
        assert "empty" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_timeout_is_bounded(self) -> None:
        session = _FakeSession()
        ctx = _FakeCtx(session)

        await verify_poc.on_invoke_tool(ctx, json.dumps({"script": "sleep", "timeout_s": 99999}))

        _, kwargs = session.calls[0]
        assert kwargs["timeout"] <= verify.MAX_TIMEOUT_S


class TestLedger:
    @pytest.mark.asyncio
    async def test_records_under_finding_key(self) -> None:
        session = _FakeSession(_FakeExecResult(b"uid=0\n", b"", 0))
        ctx = _FakeCtx(session)

        await verify_poc.on_invoke_tool(
            ctx,
            json.dumps({"script": "id", "finding_key": "rce /ping", "expect": "uid=0"}),
        )

        record = lookup_verification("rce /ping")
        assert record is not None
        assert record.expectation_met is True
        assert record.exit_code == 0

    @pytest.mark.asyncio
    async def test_latest_run_wins(self) -> None:
        ctx = _FakeCtx(_FakeSession(_FakeExecResult(b"nope\n", b"", 1)))
        await verify_poc.on_invoke_tool(
            ctx, json.dumps({"script": "a", "finding_key": "key", "expect": "yes"})
        )
        assert lookup_verification("key").expectation_met is False

        ctx2 = _FakeCtx(_FakeSession(_FakeExecResult(b"yes\n", b"", 0)))
        await verify_poc.on_invoke_tool(
            ctx2, json.dumps({"script": "b", "finding_key": "key", "expect": "yes"})
        )
        assert lookup_verification("key").expectation_met is True

    @pytest.mark.asyncio
    async def test_no_key_means_no_ledger_entry(self) -> None:
        ctx = _FakeCtx(_FakeSession())
        await verify_poc.on_invoke_tool(ctx, json.dumps({"script": "id"}))
        assert ledger_snapshot() == {}

    def test_unverified_finding_has_no_record(self) -> None:
        # Kịch bản tấn công: agent nộp báo cáo cho thứ chưa từng chạy.
        assert lookup_verification("never-ran") is None


class TestOutputBounded:
    @pytest.mark.asyncio
    async def test_huge_output_is_truncated(self) -> None:
        big = b"A" * (verify.MAX_OUTPUT_CHARS * 3)
        ctx = _FakeCtx(_FakeSession(_FakeExecResult(big, b"", 0)))

        result = _payload(await verify_poc.on_invoke_tool(ctx, json.dumps({"script": "cat big"})))

        assert len(result["output"]) <= verify.MAX_OUTPUT_CHARS + 120
        assert "cắt bớt" in result["output"]


class TestRecordsReceiptForGrounding:
    @pytest.mark.asyncio
    async def test_output_becomes_grounding_receipt(self) -> None:

        receipt_store.reset_receipts()
        output = "PORT   STATE SERVICE\n22/tcp open  ssh\n"
        ctx = _FakeCtx(_FakeSession(_FakeExecResult(output.encode(), b"", 0)))

        await verify_poc.on_invoke_tool(ctx, json.dumps({"script": "nmap"}))

        receipts = receipt_store.receipts_for("agent-1")
        assert receipts, "output PoC phải trở thành receipt cho evidence grounding"
        assert "22/tcp" in receipts[0]
        receipt_store.reset_receipts()


class TestVerificationRecordSerialization:
    def test_to_dict_round_trips(self) -> None:
        record = VerificationRecord(
            verification_id="abc123",
            finding_key="sqli /user",
            language="bash",
            exit_code=0,
            duration_s=1.5,
            output="ok",
            expectation="ok",
            expectation_met=True,
            ran=True,
        )
        data = record.to_dict()
        assert data["verification_id"] == "abc123"
        assert data["expectation_met"] is True
        assert data["ran"] is True
