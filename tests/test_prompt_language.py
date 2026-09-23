"""Test: chỉ dẫn ngôn ngữ báo cáo trong system prompt.

Chứng minh rằng prompt chỉ thêm khối chỉ dẫn tiếng Việt khi STRIX_LANG=vi, và
rằng các ràng buộc "không dịch" được ghi rõ — nếu thiếu, model sẽ dịch cả
payload và tên lỗ hổng, làm hỏng giá trị kỹ thuật của báo cáo.
"""

from __future__ import annotations

import pytest

from strix.agents.prompt import render_system_prompt
from strix.utils.labels import set_language


@pytest.fixture(autouse=True)
def _reset() -> None:
    set_language(None)
    yield
    set_language(None)


def _render() -> str:
    return render_system_prompt(scan_mode="quick", is_root=True)


class TestLanguageDirectivePresence:
    def test_no_directive_when_english(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("STRIX_LANG", raising=False)
        set_language(None)
        prompt = _render()
        assert "<report_language>" not in prompt
        assert "Vietnamese with full diacritics" not in prompt

    def test_directive_present_when_vietnamese(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("STRIX_LANG", "vi")
        set_language(None)
        prompt = _render()
        assert "<report_language>" in prompt
        assert "Vietnamese with full diacritics" in prompt

    def test_directive_block_is_well_formed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("STRIX_LANG", "vi")
        set_language(None)
        prompt = _render()
        assert prompt.count("<report_language>") == 1
        assert prompt.count("</report_language>") == 1
        assert prompt.index("<report_language>") < prompt.index("</report_language>")


class TestDirectiveCoversReportFields:
    """Mọi trường người đọc được phải được nêu tên, nếu không model sẽ bỏ sót."""

    @pytest.mark.parametrize(
        "field",
        [
            "title",
            "description",
            "impact",
            "technical_analysis",
            "poc_description",
            "remediation_steps",
            "assumptions",
            "counterevidence",
            "confidence_rationale",
            "severity_change_conditions",
            "fix_verification",
        ],
    )
    def test_field_named(self, monkeypatch: pytest.MonkeyPatch, field: str) -> None:
        monkeypatch.setenv("STRIX_LANG", "vi")
        set_language(None)
        assert f"`{field}`" in _render()


class TestDirectiveProtectsTechnicalContent:
    """Ràng buộc 'không dịch' là phần quan trọng nhất của chỉ dẫn."""

    def test_payloads_and_code_preserved(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("STRIX_LANG", "vi")
        set_language(None)
        prompt = _render()
        assert "Exploit payloads" in prompt
        assert "ORIGINAL form" in prompt

    def test_vulnerability_class_names_listed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("STRIX_LANG", "vi")
        set_language(None)
        prompt = _render()
        for term in ("SQL injection", "XSS", "SSRF", "IDOR", "RCE"):
            assert term in prompt, f"thiếu thuật ngữ được bảo vệ: {term}"

    def test_identifiers_listed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("STRIX_LANG", "vi")
        set_language(None)
        prompt = _render()
        for term in ("CVE IDs", "CWE IDs", "CVSS vectors"):
            assert term in prompt

    def test_evidence_quoted_verbatim(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("STRIX_LANG", "vi")
        set_language(None)
        # Bằng chứng phải trích nguyên văn — nếu model diễn giải lại thì phá
        # chính cơ chế evidence grounding.
        assert "quote real command output verbatim" in _render()

    def test_requires_proper_diacritics(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("STRIX_LANG", "vi")
        set_language(None)
        assert "never ASCII-only" in _render()


class TestOtherLanguagesUnaffected:
    def test_unsupported_language_adds_no_directive(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("STRIX_LANG", "fr")
        set_language(None)
        assert "<report_language>" not in _render()

    def test_explicit_english_adds_no_directive(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("STRIX_LANG", "en")
        set_language(None)
        assert "<report_language>" not in _render()


class TestPromptStillRendersWithSkills:
    """Không được làm vỡ việc render prompt với skill và các chế độ khác nhau."""

    def test_root_prompt_renders(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("STRIX_LANG", "vi")
        set_language(None)
        prompt = render_system_prompt(
            skills=["vietnam_web_targets"], scan_mode="deep", is_root=True
        )
        assert len(prompt) > 10_000
        assert "<report_language>" in prompt

    def test_child_prompt_renders(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("STRIX_LANG", "vi")
        set_language(None)
        prompt = render_system_prompt(scan_mode="quick", is_root=False)
        assert len(prompt) > 5_000
        assert "<report_language>" in prompt

    def test_interactive_prompt_renders(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("STRIX_LANG", "vi")
        set_language(None)
        prompt = render_system_prompt(scan_mode="quick", is_root=True, interactive=True)
        assert "<report_language>" in prompt
