"""Kiểm chứng bằng chứng dựa trên receipt thật.

Vấn đề: trường ``evidence`` của báo cáo lỗ hổng hiện chỉ được kiểm tra là
"không rỗng". Model chỉ cần gõ một câu nghe hợp lý là qua — không ai đối chiếu
với output lệnh thật. Đây là lỗ hổng chống bịa lớn nhất của Strix.

Module này port logic grounding từ PentestGPT (``execution.py``) để bắt buộc
bằng chứng phải là một lát cắt liền mạch chính xác của một receipt có thật do
runtime quan sát, chứ không phải lời kể lại của model.

Nguồn gốc: PentestGPT ``pentestgpt_agent/src/pentestgpt_agent/execution.py``
(USENIX Security 2024, MIT license).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass


logger = logging.getLogger(__name__)

# Trần kích thước một lát cắt bằng chứng (port từ PentestGPT).
MAX_EVIDENCE_SPAN = 4_000


class EvidenceUnverifiableError(ValueError):
    """Bằng chứng không khớp được với bất kỳ receipt thật nào."""


@dataclass(frozen=True)
class EvidenceMatch:
    """Kết quả đối chiếu bằng chứng với receipt."""

    #: Bằng chứng có khớp chính xác (sau khi chuẩn hoá xuống dòng) không.
    exact: bool
    #: Lát cắt thật lấy ra từ receipt (khác bằng chứng nếu phải nới/mở rộng).
    matched_text: str
    #: Cách khớp: "exact" | "widened" | "envelope" | "none".
    method: str

    @property
    def verified(self) -> bool:
        return self.method != "none"


def normalize_newlines_with_offsets(value: str) -> tuple[str, tuple[int, ...]]:
    """Chuẩn hoá CRLF/CR về LF, giữ bảng ánh xạ vị trí về chuỗi gốc.

    Đây là phép chuẩn hoá **duy nhất** được phép khi đối chiếu bằng chứng.
    Mọi biến đổi khác (viết hoa, bỏ dấu, rút gọn) đều làm bằng chứng mất giá trị.
    """
    characters: list[str] = []
    offsets: list[int] = []
    index = 0
    while index < len(value):
        offsets.append(index)
        if value.startswith("\r\n", index):
            characters.append("\n")
            index += 2
        elif value[index] == "\r":
            characters.append("\n")
            index += 1
        else:
            characters.append(value[index])
            index += 1
    return "".join(characters), tuple(offsets)


def _map_span_to_original(
    output: str, offsets: tuple[int, ...], start: int, end: int
) -> str:
    """Ánh xạ một khoảng trong chuỗi đã chuẩn hoá về chuỗi gốc."""
    original_start = offsets[start] if start < len(offsets) else len(output)
    original_end = offsets[end] if end < len(offsets) else len(output)
    return output[original_start:original_end]


def exact_receipt_slice(output: str, excerpt: str) -> str | None:
    """Trả về lát cắt chính xác của ``output`` khớp ``excerpt``, hoặc ``None``.

    Thử khớp nguyên văn trước; nếu không được thì chuẩn hoá CRLF/CR về LF rồi
    thử lại — đúng như PentestGPT làm, không nới lỏng thêm.
    """
    if not excerpt or not output:
        return None

    exact_start = output.find(excerpt)
    if exact_start >= 0:
        return output[exact_start : exact_start + len(excerpt)]

    normalized_output, offsets = normalize_newlines_with_offsets(output)
    normalized_excerpt, _ = normalize_newlines_with_offsets(excerpt)
    normalized_start = normalized_output.find(normalized_excerpt)
    if normalized_start < 0:
        return None
    normalized_end = normalized_start + len(normalized_excerpt)
    return _map_span_to_original(output, offsets, normalized_start, normalized_end)


def _output_lines_with_offsets(normalized_output: str) -> list[tuple[str, int, int]]:
    """Tách dòng kèm vị trí (start, end) trong chuỗi đã chuẩn hoá."""
    lines: list[tuple[str, int, int]] = []
    cursor = 0
    for line_with_ending in normalized_output.splitlines(keepends=True):
        line = line_with_ending.removesuffix("\n")
        lines.append((line, cursor, cursor + len(line)))
        cursor += len(line_with_ending)
    # Phần đuôi không có ký tự xuống dòng.
    if cursor < len(normalized_output):
        lines.append((normalized_output[cursor:], cursor, len(normalized_output)))
    return lines


def unique_line_envelope(output: str, wanted_lines: list[str]) -> str | None:
    """Dựng khoảng bao từ các dòng **xuất hiện đúng một lần**.

    Chỉ nhận khi mọi dòng đều không rỗng, không trùng nhau, và xuất hiện đúng
    một lần trong output. Đây là điều kiện chống khớp mơ hồ: một dòng lặp lại
    thì không định vị được vị trí thật, nên phải từ chối thay vì đoán.
    """
    if not wanted_lines or len(set(wanted_lines)) != len(wanted_lines):
        return None
    if any(not line.strip() for line in wanted_lines):
        return None

    normalized_output, offsets = normalize_newlines_with_offsets(output)
    output_lines = _output_lines_with_offsets(normalized_output)

    matched: list[tuple[int, int]] = []
    for wanted in wanted_lines:
        occurrences = [
            (line_start, line_end)
            for line, line_start, line_end in output_lines
            if line == wanted
        ]
        if len(occurrences) != 1:
            return None
        matched.append(occurrences[0])

    start = min(line_start for line_start, _ in matched)
    end = max(line_end for _, line_end in matched)
    span = _map_span_to_original(output, offsets, start, end)
    return span if len(span) <= MAX_EVIDENCE_SPAN else None


def exact_unique_line_envelope(output: str, excerpt: str) -> str | None:
    """Khôi phục khoảng thật từ tập dòng chính xác, rõ ràng (cần >= 4 dòng)."""
    normalized_excerpt, _ = normalize_newlines_with_offsets(excerpt)
    wanted_lines = [line for line in normalized_excerpt.splitlines() if line]
    if len(wanted_lines) < 4:
        return None
    return unique_line_envelope(output, wanted_lines)


def ordered_exact_line_span(output: str, excerpt: str) -> str | None:
    """Nới các dòng khớp theo đúng thứ tự thành một khoảng liền mạch có trần.

    Dùng khi bằng chứng là nhiều dòng rời rạc nhưng thứ tự đúng — chấp nhận
    khoảng bao giữa dòng đầu và dòng cuối, miễn không vượt trần.
    """
    normalized_output, offsets = normalize_newlines_with_offsets(output)
    normalized_excerpt, _ = normalize_newlines_with_offsets(excerpt)
    wanted_lines = normalized_excerpt.splitlines()
    if len(wanted_lines) < 2 or any(not line for line in wanted_lines):
        return None

    output_lines = _output_lines_with_offsets(normalized_output)

    matched: list[tuple[int, int]] = []
    search_from = 0
    for wanted in wanted_lines:
        for index in range(search_from, len(output_lines)):
            line, line_start, line_end = output_lines[index]
            if line != wanted:
                continue
            matched.append((line_start, line_end))
            search_from = index + 1
            break
        else:
            return None

    start = matched[0][0]
    end = matched[-1][1]
    span = _map_span_to_original(output, offsets, start, end)
    return span if len(span) <= MAX_EVIDENCE_SPAN else None


def verify_evidence(evidence: str, receipts: list[str]) -> EvidenceMatch:
    """Đối chiếu ``evidence`` với các receipt thật, theo thứ tự chặt dần.

    Thứ tự thử (chặt → lỏng):
      1. Khớp nguyên văn / chỉ chuẩn hoá xuống dòng.
      2. Khoảng bao từ các dòng rõ ràng, duy nhất.
      3. Nới các dòng khớp theo đúng thứ tự.

    Trả về ``EvidenceMatch`` với ``method == "none"`` nếu không khớp gì.
    """
    if not evidence or not evidence.strip():
        return EvidenceMatch(exact=False, matched_text="", method="none")

    for receipt in receipts:
        if not receipt:
            continue

        span = exact_receipt_slice(receipt, evidence)
        if span is not None:
            return EvidenceMatch(exact=True, matched_text=span, method="exact")

        span = exact_unique_line_envelope(receipt, evidence)
        if span is not None:
            return EvidenceMatch(exact=False, matched_text=span, method="envelope")

        span = ordered_exact_line_span(receipt, evidence)
        if span is not None:
            return EvidenceMatch(exact=False, matched_text=span, method="widened")

    return EvidenceMatch(exact=False, matched_text="", method="none")


_EVIDENCE_BLOCK_RE = re.compile(
    r"```[^\n]*\n(?P<body>.*?)```",
    re.DOTALL,
)


def extract_evidence_blocks(evidence: str) -> list[str]:
    """Tách các khối code trong ``evidence`` để đối chiếu từng khối.

    Báo cáo thường nhúng output thật trong khối ```. Đối chiếu cả khối lẫn
    phần văn xuôi giúp không bỏ sót bằng chứng hợp lệ.
    """
    blocks = [m.group("body").strip("\n") for m in _EVIDENCE_BLOCK_RE.finditer(evidence)]
    return [b for b in blocks if b.strip()]


def verify_evidence_candidates(evidence: str, receipts: list[str]) -> EvidenceMatch:
    """Đối chiếu lần lượt toàn bộ ``evidence``, rồi từng khối code bên trong.

    Lấy kết quả đầu tiên khớp được — chỉ cần **một phần** bằng chứng neo được
    vào receipt thật là đủ để chứng minh model không bịa.
    """
    overall = verify_evidence(evidence, receipts)
    if overall.verified:
        return overall

    for block in extract_evidence_blocks(evidence):
        match = verify_evidence(block, receipts)
        if match.verified:
            return match

    return overall
