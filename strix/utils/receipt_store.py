"""Kho receipt thật của tool, dùng để kiểm chứng bằng chứng.

Strix không lưu lại output của ``exec_command`` ở dạng truy được theo agent để
đối chiếu về sau. Module này giữ một cửa sổ trượt (bounded) các kết quả tool
theo từng agent, làm nguồn đối chiếu cho
:mod:`strix.utils.evidence_grounding`.

Thiết kế có chủ đích:

- **Bounded**: chỉ giữ ``_MAX_RECEIPTS_PER_AGENT`` receipt gần nhất và cắt mỗi
  receipt ở ``_MAX_RECEIPT_CHARS``. Không phình bộ nhớ trong scan dài.
- **Chỉ đọc**: đây là bản ghi quan sát của runtime, không phải bộ nhớ của agent.
  Ghi vào đây không thay đổi hành vi tool.
- **Theo agent**: mỗi agent chỉ đối chiếu được với chính những gì nó (hoặc cả
  run) đã chạy — không thể "mượn" output của agent khác làm bằng chứng.
"""

from __future__ import annotations

import logging
import threading
from collections import OrderedDict, deque
from typing import Any


logger = logging.getLogger(__name__)

#: Số receipt giữ lại cho mỗi agent.
_MAX_RECEIPTS_PER_AGENT = 200
#: Trần ký tự mỗi receipt (khớp trần tool output của Strix).
_MAX_RECEIPT_CHARS = 50 * 1024
#: Số agent tối đa theo dõi (chặn rò rỉ bộ nhớ nếu agent id sinh vô hạn).
_MAX_TRACKED_AGENTS = 128

#: Tool mà output của nó KHÔNG phải bằng chứng quan sát được.
#: Suy luận, ghi chú, và điều phối là nội bộ — không chứng minh được gì về target.
_NON_EVIDENCE_TOOLS = frozenset(
    {
        "think",
        "create_todo",
        "list_todos",
        "update_todo",
        "mark_todo_done",
        "mark_todo_pending",
        "delete_todo",
        "create_note",
        "list_notes",
        "get_note",
        "update_note",
        "delete_note",
        "load_skill",
        "list_coverage",
        "view_agent_graph",
        "wait_for_agents",
        "send_message_to_agent",
        "get_threat_model",
        "save_threat_model",
        "amend_threat_model",
        "list_reports",
        "get_report",
        "create_vulnerability_report",
        "create_dependency_report",
        "update_vulnerability_report",
        "respond_to_user",
    }
)

_receipts: OrderedDict[str, deque[tuple[str, str]]] = OrderedDict()
_lock = threading.RLock()


def _normalize_agent_id(value: Any) -> str:
    return value if isinstance(value, str) and value else "__unknown__"


def _truncate(text: str) -> str:
    if len(text) <= _MAX_RECEIPT_CHARS:
        return text
    # Giữ cả đầu và đuôi: đường dẫn file, dòng lỗi, và mã thoát thường nằm ở đuôi.
    head = _MAX_RECEIPT_CHARS // 2
    tail = _MAX_RECEIPT_CHARS - head
    return f"{text[:head]}\n[... cắt bớt ...]\n{text[-tail:]}"


def record_receipt(agent_id: Any, tool_name: str, result: Any) -> None:
    """Ghi một kết quả tool làm receipt quan sát được.

    Bỏ qua tool nội bộ (xem ``_NON_EVIDENCE_TOOLS``) và kết quả không phải chuỗi,
    vì chúng không chứng minh được điều gì về target.
    """
    if not isinstance(result, str) or not result.strip():
        return
    if tool_name in _NON_EVIDENCE_TOOLS:
        return

    key = _normalize_agent_id(agent_id)
    text = _truncate(result)

    with _lock:
        bucket = _receipts.get(key)
        if bucket is None:
            bucket = deque(maxlen=_MAX_RECEIPTS_PER_AGENT)
            _receipts[key] = bucket
            while len(_receipts) > _MAX_TRACKED_AGENTS:
                _receipts.popitem(last=False)
        else:
            _receipts.move_to_end(key)
        bucket.append((tool_name, text))


def receipts_for(agent_id: Any) -> list[str]:
    """Receipt của riêng một agent, cũ nhất trước."""
    key = _normalize_agent_id(agent_id)
    with _lock:
        bucket = _receipts.get(key)
        return [text for _, text in bucket] if bucket else []


def all_receipts() -> list[str]:
    """Receipt của toàn bộ run — dùng khi root agent tổng hợp phát hiện của agent con."""
    out: list[str] = []
    with _lock:
        for bucket in _receipts.values():
            out.extend(text for _, text in bucket)
    return out


def receipts_for_verification(agent_id: Any) -> list[str]:
    """Bộ receipt để đối chiếu: của agent trước, rồi bổ sung phần còn lại của run.

    Ưu tiên receipt của chính agent để một agent không thể lấy output của agent
    khác làm bằng chứng cho việc mình chưa từng làm; chỉ khi agent đó không có
    receipt nào mới fallback sang toàn run (trường hợp root tổng hợp).
    """
    own = receipts_for(agent_id)
    if own:
        return own
    return all_receipts()


def reset_receipts() -> None:
    """Xoá sạch kho receipt. Gọi ở đầu mỗi scan."""
    with _lock:
        _receipts.clear()


def receipt_stats() -> dict[str, int]:
    """Thống kê nhanh, phục vụ chẩn đoán và test."""
    with _lock:
        return {agent: len(bucket) for agent, bucket in _receipts.items()}
