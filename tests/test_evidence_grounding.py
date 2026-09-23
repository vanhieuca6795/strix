"""Test cho module evidence_grounding — chứng minh chống bịa hoạt động."""

from __future__ import annotations

from strix.utils.evidence_grounding import (
    exact_receipt_slice,
    exact_unique_line_envelope,
    extract_evidence_blocks,
    normalize_newlines_with_offsets,
    ordered_exact_line_span,
    unique_line_envelope,
    verify_evidence,
    verify_evidence_candidates,
)


RECEIPT = """$ nmap -sV 10.10.11.234
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 10.10.11.234
Host is up (0.021s latency).
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
80/tcp open  http    nginx 1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Nmap done: 1 IP address (1 host up) scanned in 12.34 seconds
"""


class TestNewlineNormalization:
    def test_crlf_becomes_lf(self) -> None:
        text = "a\r\nb\r\nc"
        normalized, offsets = normalize_newlines_with_offsets(text)
        assert normalized == "a\nb\nc"
        assert offsets[0] == 0
        assert offsets[2] == 3  # 'b' ở vị trí 3 trong chuỗi gốc

    def test_bare_cr_becomes_lf(self) -> None:
        normalized, _ = normalize_newlines_with_offsets("a\rb")
        assert normalized == "a\nb"

    def test_offsets_map_back_to_original(self) -> None:
        text = "line1\r\nline2"
        normalized, offsets = normalize_newlines_with_offsets(text)

        start = normalized.index("line2")
        end = start + len("line2")
        original_start = offsets[start]
        # Vượt qua cuối bảng ánh xạ nghĩa là chạm cuối chuỗi gốc.
        original_end = offsets[end] if end < len(offsets) else len(text)

        assert text[original_start:original_end] == "line2"
        assert original_start == 7  # sau '\r\n'


class TestExactReceiptSlice:
    def test_exact_match_returns_slice(self) -> None:
        excerpt = "22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5"
        result = exact_receipt_slice(RECEIPT, excerpt)
        assert result == excerpt

    def test_crlf_in_receipt_still_matches(self) -> None:
        crlf_receipt = RECEIPT.replace("\n", "\r\n")
        excerpt = "80/tcp open  http    nginx 1.18.0"
        assert exact_receipt_slice(crlf_receipt, excerpt) == excerpt

    def test_fabricated_evidence_returns_none(self) -> None:
        # Model bịa một dòng trông rất hợp lý nhưng không hề có trong output.
        fabricated = "4444/tcp open  vnc     VNC 4.1.1"
        assert exact_receipt_slice(RECEIPT, fabricated) is None

    def test_empty_inputs_return_none(self) -> None:
        assert exact_receipt_slice(RECEIPT, "") is None
        assert exact_receipt_slice("", "anything") is None


class TestUniqueLineEnvelope:
    def test_unique_lines_build_envelope(self) -> None:
        wanted = [
            "Nmap scan report for 10.10.11.234",
            "Host is up (0.021s latency).",
        ]
        span = unique_line_envelope(RECEIPT, wanted)
        assert span is not None
        assert "10.10.11.234" in span
        assert "latency" in span

    def test_ambiguous_line_rejected(self) -> None:
        # Dòng này xuất hiện 2 lần -> không định vị được -> phải từ chối.
        receipt = "state: open\nsomething else\nstate: open\n"
        assert unique_line_envelope(receipt, ["state: open"]) is None

    def test_duplicate_wanted_lines_rejected(self) -> None:
        assert unique_line_envelope(RECEIPT, ["PORT   STATE SERVICE VERSION"] * 2) is None

    def test_blank_line_rejected(self) -> None:
        assert unique_line_envelope(RECEIPT, ["PORT   STATE SERVICE VERSION", "   "]) is None


class TestExactUniqueLineEnvelope:
    def test_four_exact_lines_recovered(self) -> None:
        excerpt = (
            "PORT   STATE SERVICE VERSION\n"
            "22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5\n"
            "80/tcp open  http    nginx 1.18.0\n"
            "Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel"
        )
        span = exact_unique_line_envelope(RECEIPT, excerpt)
        assert span is not None
        assert "22/tcp" in span and "80/tcp" in span and "Service Info" in span

    def test_fewer_than_four_lines_rejected(self) -> None:
        short = "PORT   STATE SERVICE VERSION\n22/tcp open"
        assert exact_unique_line_envelope(RECEIPT, short) is None

    def test_partial_line_rejected(self) -> None:
        # Dòng cuối bị cắt cụt, không tồn tại nguyên văn -> phải từ chối.
        excerpt = (
            "PORT   STATE SERVICE VERSION\n"
            "22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5\n"
            "80/tcp open  http    nginx 1.18.0\n"
            "Service Info: OS: Linux"
        )
        assert exact_unique_line_envelope(RECEIPT, excerpt) is None

    def test_fabricated_lines_rejected(self) -> None:
        excerpt = (
            "PORT   STATE SERVICE VERSION\n"
            "22/tcp open  ssh     OpenSSH 9.9p1\n"
            "80/tcp open  http    nginx 9.9.9\n"
            "Service Info: OS: FreeBSD"
        )
        assert exact_unique_line_envelope(RECEIPT, excerpt) is None


class TestOrderedExactLineSpan:
    def test_ordered_partial_lines_span(self) -> None:
        excerpt = (
            "22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5\n"
            "Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel"
        )
        span = ordered_exact_line_span(RECEIPT, excerpt)
        assert span is not None
        assert "22/tcp" in span and "Service Info" in span

    def test_out_of_order_rejected(self) -> None:
        # Đảo thứ tự -> không phải khoảng liền mạch -> phải từ chối.
        excerpt = (
            "Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel\n"
            "22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5"
        )
        assert ordered_exact_line_span(RECEIPT, excerpt) is None

    def test_single_line_rejected(self) -> None:
        assert ordered_exact_line_span(RECEIPT, "PORT   STATE SERVICE VERSION") is None

    def test_fabricated_line_rejected(self) -> None:
        excerpt = (
            "22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5\n"
            "3306/tcp open  mysql   MySQL 5.7.38"
        )
        assert ordered_exact_line_span(RECEIPT, excerpt) is None


class TestVerifyEvidence:
    def test_real_evidence_verifies_as_exact(self) -> None:
        match = verify_evidence("80/tcp open  http    nginx 1.18.0", [RECEIPT])
        assert match.verified
        assert match.method == "exact"
        assert match.exact is True

    def test_fabricated_evidence_not_verified(self) -> None:
        match = verify_evidence("4444/tcp open vnc VNC 4.1.1", [RECEIPT])
        assert not match.verified
        assert match.method == "none"
        assert match.matched_text == ""

    def test_empty_evidence_not_verified(self) -> None:
        assert not verify_evidence("", [RECEIPT]).verified
        assert not verify_evidence("   ", [RECEIPT]).verified

    def test_matches_against_second_receipt(self) -> None:
        other = "$ whoami\nwww-data\n"
        match = verify_evidence("www-data", [RECEIPT, other])
        assert match.verified
        assert match.method == "exact"

    def test_no_receipts_not_verified(self) -> None:
        assert not verify_evidence("anything", []).verified


class TestExtractEvidenceBlocks:
    def test_extracts_fenced_blocks(self) -> None:
        evidence = "Port scan cho thấy:\n```\n22/tcp open ssh\n```\nKết luận: SSH lộ ra ngoài."
        blocks = extract_evidence_blocks(evidence)
        assert blocks == ["22/tcp open ssh"]

    def test_multiple_blocks(self) -> None:
        evidence = "```\nblock one\n```\ntext\n```\nblock two\n```"
        assert extract_evidence_blocks(evidence) == ["block one", "block two"]

    def test_no_blocks_returns_empty(self) -> None:
        assert extract_evidence_blocks("Chỉ là văn xuôi, không có khối code.") == []


class TestVerifyEvidenceCandidates:
    def test_evidence_wrapped_in_prose_still_verifies(self) -> None:
        evidence = (
            "Quét cổng phát hiện dịch vụ SSH lộ ra ngoài:\n"
            "```\n"
            "22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5\n"
            "```\n"
            "Đây là rủi ro trung bình vì SSH cho phép thử mật khẩu từ Internet."
        )
        match = verify_evidence_candidates(evidence, [RECEIPT])
        assert match.verified
        assert "22/tcp" in match.matched_text

    def test_fully_fabricated_prose_rejected(self) -> None:
        evidence = (
            "Hệ thống chạy PostgreSQL 14 trên cổng 5432 và có lỗ hổng "
            "CVE-2024-99999 cho phép thực thi mã từ xa không cần xác thực."
        )
        assert not verify_evidence_candidates(evidence, [RECEIPT]).verified


class TestSecurityGuarantee:
    """Các test khẳng định bảo đảm cốt lõi: không thể bịa bằng chứng."""

    def test_plausible_fabrication_is_caught(self) -> None:
        # Kịch bản tấn công thật: model viết một báo cáo nghe rất thuyết phục,
        # trích "output" trông y như nmap thật nhưng không hề chạy lệnh đó.
        fake_report_evidence = (
            "Kết quả quét dịch vụ:\n"
            "```\n"
            "Starting Nmap 7.94 ( https://nmap.org )\n"
            "Nmap scan report for 10.10.11.234\n"
            "PORT     STATE SERVICE VERSION\n"
            "3306/tcp open  mysql   MySQL 5.7.38\n"
            "6379/tcp open  redis   Redis key-value store 6.2.7\n"
            "```\n"
            "Cả MySQL và Redis đều lộ ra Internet."
        )
        match = verify_evidence_candidates(fake_report_evidence, [RECEIPT])
        assert not match.verified, "Bằng chứng bịa KHÔNG được phép qua cửa kiểm chứng"

    def test_single_real_line_among_fabrications_still_verifies(self) -> None:
        # Ranh giới có chủ đích: chỉ cần một phần neo được vào receipt thật là
        # đủ chứng minh model thực sự đã chạy lệnh. Việc phán xét phần diễn giải
        # thuộc về con người/agent, không phải module này.
        mixed = (
            "Quét được:\n```\n80/tcp open  http    nginx 1.18.0\n```\n"
            "ngoài ra tôi đoán có MySQL."
        )
        match = verify_evidence_candidates(mixed, [RECEIPT])
        assert match.verified
        assert match.matched_text == "80/tcp open  http    nginx 1.18.0"
