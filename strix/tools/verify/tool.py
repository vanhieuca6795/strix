"""``verify_poc`` - chạy PoC thật trong sandbox và lấy output làm bằng chứng.

VẤN ĐỀ ĐO ĐƯỢC:
``poc_script_code`` của báo cáo lỗ hổng chỉ được kiểm tra là **"không rỗng"**
(``_REQUIRED_FIELDS`` trong ``strix/tools/reporting/tool.py``). Không có gì
chạy nó. Nghĩa là agent có thể mô tả một PoC nghe rất hợp lý mà **chưa từng
chạy thành công** - và báo cáo vẫn ra, không ai biết.

``fix_verification`` còn cho phép ghi "reasoned" (chỉ suy luận, không chạy).

Hệ quả với chủ hệ thống được kiểm thử: họ nhận một tuyên bố "có lỗ hổng" kèm
đoạn mã trông đúng, nhưng không có bằng chứng nào cho thấy nó thật sự chạy.
Đó là điểm yếu chí mạng của một báo cáo bảo mật.

CÁCH VÁ:
Tool này chạy PoC **trong sandbox thật**, ghi lại mã thoát + output thô, và
lưu vào sổ kiểm chứng. Báo cáo lỗ hổng sau đó đối chiếu với sổ này.

Nguyên tắc:
- **Không bao giờ ném lỗi ra ngoài.** PoC hỏng là thông tin hữu ích, không
  phải sự cố của cuộc quét.
- **Luôn trả output thô.** Dù PoC thất bại, output vẫn là bằng chứng.
- **Có trần thời gian.** PoC treo không được treo cả cuộc quét.
- **Ghi vào receipt store** để cơ chế evidence grounding hiện có chấp nhận
  chính output này làm bằng chứng.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)

#: Ngôn ngữ PoC được hỗ trợ.
PocLanguage = Literal["bash", "sh", "python"]

#: Trần thời gian một lần chạy PoC (giây).
DEFAULT_TIMEOUT_S = 180
MAX_TIMEOUT_S = 900

#: Trần ký tự output trả về model (đủ để đọc, không làm ngập context).
MAX_OUTPUT_CHARS = 8_000


@dataclass
class VerificationRecord:
    """Một lần chạy PoC, lưu trong sổ kiểm chứng."""

    verification_id: str
    finding_key: str
    language: str
    exit_code: int
    duration_s: float
    output: str
    expectation: str = ""
    expectation_met: bool = False
    ran: bool = False
    error: str | None = None
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


#: Sổ kiểm chứng theo phiên, khoá là ``finding_key`` (mới nhất thắng).
_LEDGER: dict[str, VerificationRecord] = {}


def _ctx_inner(ctx: Any) -> dict[str, Any]:
    context = getattr(ctx, "context", None)
    return context if isinstance(context, dict) else {}


def _sandbox_session(ctx: Any) -> Any | None:
    """Lấy sandbox session từ context do runner bơm vào."""
    return _ctx_inner(ctx).get("sandbox_session")


def _agent_id(ctx: Any) -> str | None:
    raw = _ctx_inner(ctx).get("agent_id")
    return raw if isinstance(raw, str) else None


def _bounded(text: str, limit: int = MAX_OUTPUT_CHARS) -> str:
    if len(text) <= limit:
        return text
    head = limit // 2
    tail = limit - head
    return f"{text[:head]}\n[... cắt bớt {len(text) - limit} ký tự ...]\n{text[-tail:]}"


def ledger_snapshot() -> dict[str, VerificationRecord]:
    """Bản sao sổ kiểm chứng, dùng cho reporting và test."""
    return dict(_LEDGER)


def lookup_verification(finding_key: str) -> VerificationRecord | None:
    """Tra một lần kiểm chứng theo khoá phát hiện."""
    return _LEDGER.get(finding_key.strip()) if finding_key else None


def reset_ledger() -> None:
    """Xoá sổ kiểm chứng. Gọi ở đầu mỗi scan."""
    _LEDGER.clear()


def _build_command(script: str, language: str) -> list[str]:
    if language == "python":
        return ["python3", "-c", script]
    # ``bash`` và ``sh`` đều chạy qua bash để có đủ cú pháp hiện đại.
    return ["bash", "-lc", script]


def _extract(result: Any) -> tuple[int, str]:
    """Lấy mã thoát và output gộp từ ``ExecResult`` của SDK."""
    exit_code = int(getattr(result, "exit_code", 1) or 0)
    parts: list[str] = []
    for attr in ("stdout", "stderr"):
        raw = getattr(result, attr, None)
        if raw is None:
            continue
        parts.append(raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw))
    return exit_code, "\n".join(part for part in parts if part)


async def _run_poc(
    session: Any, script: str, language: str, timeout_s: float
) -> tuple[bool, int, str, str | None, float]:
    """Chạy PoC trong sandbox. Trả (đã chạy, mã thoát, output, lỗi, thời lượng)."""
    command = _build_command(script, language)
    started = time.monotonic()
    try:
        result = await asyncio.wait_for(
            session.exec(*command, timeout=timeout_s),
            timeout=timeout_s + 30,
        )
    except TimeoutError:
        return (
            False,
            124,
            "",
            f"PoC vượt quá {timeout_s:.0f} giây và bị dừng. "
            "Rút ngắn PoC hoặc tăng `timeout_s`.",
            time.monotonic() - started,
        )
    except Exception as exc:  # noqa: BLE001 - sandbox có thể đã chết
        return False, 1, "", f"không chạy được PoC trong sandbox: {exc}", time.monotonic() - started

    exit_code, output = _extract(result)
    return True, exit_code, output, None, time.monotonic() - started


def _record_receipt(ctx: Any, output: str) -> None:
    """Ghi output PoC vào receipt store để evidence grounding chấp nhận."""
    if not output.strip():
        return
    try:
        from strix.utils.receipt_store import record_receipt  # noqa: PLC0415 - tránh vòng import

        record_receipt(_agent_id(ctx), "verify_poc", output)
    except Exception:  # noqa: BLE001 - ghi nhận là phụ trợ
        logger.debug("ghi receipt cho verify_poc thất bại", exc_info=True)


def _save_artifact(ctx: Any, record: VerificationRecord, output: str) -> str | None:
    """Lưu output PoC thành artifact chứng cứ, trả đường dẫn tương đối."""
    run_dir_raw = _ctx_inner(ctx).get("run_dir")
    if not run_dir_raw:
        return None
    try:
        root = Path(str(run_dir_raw)) / "evidence" / "verification"
        root.mkdir(parents=True, exist_ok=True)
        target = root / f"{record.verification_id}.txt"
        sep = "=" * 72
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created_at))
        header = (
            f"# Kiểm chứng PoC {record.verification_id}\n"
            f"# Khoá phát hiện : {record.finding_key or '(không đặt)'}\n"
            f"# Ngôn ngữ       : {record.language}\n"
            f"# Mã thoát       : {record.exit_code}\n"
            f"# Thời lượng     : {record.duration_s:.2f}s\n"
            f"# Kỳ vọng        : {record.expectation or '(không đặt)'}\n"
            f"# Đạt kỳ vọng    : {'CÓ' if record.expectation_met else 'KHÔNG'}\n"
            f"# Thời điểm      : {stamp}\n"
            f"\n{sep}\nSCRIPT\n{sep}\n{record_poc_script(ctx)}\n"
            f"\n{sep}\nOUTPUT\n{sep}\n{output}\n"
        )
        target.write_text(header, encoding="utf-8")
        return str(target)
    except Exception:  # noqa: BLE001 - lưu artifact là phụ trợ
        logger.debug("lưu artifact kiểm chứng thất bại", exc_info=True)
        return None


#: Script PoC gần nhất theo phiên, để ghi kèm artifact.
_LAST_SCRIPT: dict[str, str] = {}


def record_poc_script(ctx: Any) -> str:
    return _LAST_SCRIPT.get(str(_agent_id(ctx)), "(không ghi lại)")


@function_tool(timeout=MAX_TIMEOUT_S + 60)
async def verify_poc(
    ctx: RunContextWrapper,
    script: str,
    language: PocLanguage = "bash",
    finding_key: str = "",
    expect: str = "",
    timeout_s: int = DEFAULT_TIMEOUT_S,
) -> str:
    """Run a proof-of-concept in the sandbox and capture its real output.

    Use this BEFORE filing a vulnerability report. A report whose PoC was
    never executed is a claim, not a finding - the person who has to fix it
    cannot tell a real exploit from a plausible-looking guess.

    What it does:
    1. Runs ``script`` inside the sandbox (same environment as your other tools).
    2. Captures stdout, stderr, and the exit code, unmodified.
    3. Checks whether ``expect`` appears in the output.
    4. Records the run so the report can cite verified evidence.

    How to write a good PoC:
    - Make it self-contained: assume nothing about prior shell state.
    - Make it decisive: print something that could ONLY appear if the
      vulnerability is real (e.g. the contents of ``/etc/passwd`` or a
      unique marker string), not just an HTTP status code.
    - Set ``expect`` to that unique marker so a match is unambiguous.

    A PoC that fails is still useful: the output tells you whether the
    hypothesis was wrong, the payload needs different quoting, or the
    target is not reachable. Report what you observed rather than
    filing on the strength of the script alone.

    Args:
        script: The proof-of-concept source to execute.
        language: ``bash`` (default), ``sh``, or ``python``.
        finding_key: Short label linking this run to a finding, so the same
            flaw does not get re-verified from scratch. Pick something
            stable like ``"sqli /user id"``.
        expect: Substring that should appear in the output if the
            vulnerability is real. Matching is case-sensitive.
        timeout_s: Kill the PoC after this many seconds (default 180,
            maximum 900). Keep it short for network probes.
    """
    text = (script or "").strip()
    if not text:
        return json.dumps(
            {"success": False, "error": "Script cannot be empty", "ran": False},
            ensure_ascii=False,
        )

    session = _sandbox_session(ctx)
    if session is None:
        return json.dumps(
            {
                "success": False,
                "ran": False,
                "error": (
                    "No sandbox session in context - PoC cannot run. This is an "
                    "environment problem, not a PoC problem; record the gap."
                ),
            },
            ensure_ascii=False,
        )

    bounded_timeout = max(5, min(int(timeout_s or DEFAULT_TIMEOUT_S), MAX_TIMEOUT_S))
    verification_id = uuid.uuid4().hex[:8]
    _LAST_SCRIPT[str(_agent_id(ctx))] = text

    ran, exit_code, output, error, duration = await _run_poc(
        session, text, language, float(bounded_timeout)
    )

    expectation = (expect or "").strip()
    expectation_met = bool(expectation) and expectation in output

    record = VerificationRecord(
        verification_id=verification_id,
        finding_key=(finding_key or "").strip(),
        language=language,
        exit_code=exit_code,
        duration_s=duration,
        output=_bounded(output),
        expectation=expectation,
        expectation_met=expectation_met,
        ran=ran,
        error=error,
    )
    if record.finding_key:
        _LEDGER[record.finding_key] = record

    _record_receipt(ctx, output)
    artifact = _save_artifact(ctx, record, output)

    payload: dict[str, Any] = {
        "success": ran,
        "verification_id": verification_id,
        "ran": ran,
        "exit_code": exit_code,
        "duration_s": round(duration, 2),
        "output": _bounded(output),
        "expectation": expectation,
        "expectation_met": expectation_met,
    }
    if artifact:
        payload["evidence_path"] = artifact
    if error:
        payload["error"] = error

    if not expectation:
        payload["hint"] = (
            "No `expect` was given, so success is undetermined. Re-run with the "
            "unique string that proves exploitation, or explain in the report "
            "why the exit code alone is conclusive."
        )
    elif not expectation_met:
        payload["hint"] = (
            f"The output does not contain {expectation!r}. Either the "
            "vulnerability is not exploitable as tested, or the PoC needs "
            "adjustment. Do not file it as confirmed until this matches, or "
            "state the gap explicitly in `assumptions`."
        )

    logger.info(
        "verify_poc %s: ran=%s exit=%s expect_met=%s (%.1fs)",
        verification_id,
        ran,
        exit_code,
        expectation_met,
        duration,
    )
    return json.dumps(payload, ensure_ascii=False, default=str)
