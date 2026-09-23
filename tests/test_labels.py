"""Test cho module labels (bản địa hoá nhãn hiển thị)."""

from __future__ import annotations

import pytest

from strix.utils.labels import (
    DEFAULT_LANGUAGE,
    SUPPORTED_LANGUAGES,
    current_language,
    is_vietnamese,
    resolve_language,
    set_language,
    severity_label,
    t,
)


@pytest.fixture(autouse=True)
def _reset_language(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_LANG", raising=False)
    set_language(None)
    yield
    set_language(None)


class TestResolveLanguage:
    def test_defaults_to_english(self) -> None:
        assert resolve_language() == "en"

    def test_reads_strix_lang(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("STRIX_LANG", "vi")
        assert resolve_language() == "vi"

    @pytest.mark.parametrize("value", ["vi", "VI", "vi-VN", "vi_VN", "Vi-vn"])
    def test_accepts_vietnamese_variants(self, monkeypatch: pytest.MonkeyPatch, value: str) -> None:
        monkeypatch.setenv("STRIX_LANG", value)
        assert resolve_language() == "vi"

    def test_unsupported_falls_back_to_english(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("STRIX_LANG", "fr")
        assert resolve_language() == "en"

    def test_empty_falls_back(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("STRIX_LANG", "")
        assert resolve_language() == "en"

    def test_set_language_overrides_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("STRIX_LANG", "vi")
        set_language("en")
        assert current_language() == "en"

    def test_supported_languages_contains_both(self) -> None:
        assert SUPPORTED_LANGUAGES == frozenset({"en", "vi"})
        assert DEFAULT_LANGUAGE == "en"


class TestTranslation:
    def test_english_default(self) -> None:
        assert t("section.evidence") == "Evidence"

    def test_vietnamese_when_set(self) -> None:
        set_language("vi")
        assert t("section.evidence") == "Bằng chứng"

    def test_vietnamese_has_diacritics(self) -> None:
        set_language("vi")
        text = t("section.remediation")
        assert text == "Khắc phục"
        # Kiểm tra dấu thật sự hiện diện, không bị mất khi truyền tải.
        assert "ắ" in text

    def test_unknown_key_returns_key(self) -> None:
        # Nhãn thiếu không được làm hỏng báo cáo.
        assert t("does.not.exist") == "does.not.exist"

    def test_format_kwargs_applied(self) -> None:
        set_language("vi")
        # Không có nhãn nào cần format hiện tại, nên chỉ kiểm tra không vỡ.
        assert t("section.impact") == "Tác động"

    def test_all_keys_have_both_languages(self) -> None:
        from strix.utils.labels import _LABELS

        missing: list[str] = []
        for key, entry in _LABELS.items():
            if not entry.get("en") or not entry.get("vi"):
                missing.append(key)
        assert not missing, f"Nhãn thiếu bản dịch: {missing}"

    def test_all_vietnamese_values_have_diacritics_or_are_technical(self) -> None:
        from strix.utils.labels import _LABELS

        diacritics = "ăâđêôơưáàảãạấầẩẫậắằẳẵặéèẻẽẹếềểễệíìỉĩịóòỏõọốồổỗộớờởỡợúùủũụứừửữựýỳỷỹỵ"
        # Hai nhóm được phép không có dấu:
        #  - thuật ngữ quốc tế giữ nguyên tiếng Anh (ID, Endpoint, Method…);
        #  - từ tiếng Việt vốn không mang dấu (ra, xem, cao…).
        allowed_keys = {
            "vuln.id",
            "vuln.cve",
            "vuln.cwe",
            "vuln.cvss",
            "vuln.method",
            "vuln.endpoint",
            "ui.output_tokens",
            "ui.view",
            "severity.high",
        }
        offenders: list[str] = []
        for key, entry in _LABELS.items():
            if key in allowed_keys:
                continue
            value = entry["vi"]
            if not any(char in diacritics or char in "ÂÊÔƠƯĐ" for char in value.casefold()):
                offenders.append(f"{key}={value!r}")
        assert not offenders, f"Nhãn tiếng Việt thiếu dấu: {offenders}"


class TestSeverityLabel:
    def test_english_labels(self) -> None:
        assert severity_label("critical") == "CRITICAL"
        assert severity_label("info") == "INFO"

    def test_vietnamese_labels(self) -> None:
        set_language("vi")
        assert severity_label("critical") == "NGHIÊM TRỌNG"
        assert severity_label("high") == "CAO"
        assert severity_label("medium") == "TRUNG BÌNH"
        assert severity_label("low") == "THẤP"

    def test_case_insensitive_input(self) -> None:
        set_language("vi")
        assert severity_label("CRITICAL") == "NGHIÊM TRỌNG"
        assert severity_label("High") == "CAO"

    def test_unknown_severity_uppercased(self) -> None:
        assert severity_label("weird") == "WEIRD"

    def test_severity_keys_stay_english_for_machine_readers(self) -> None:
        # Điểm mấu chốt: dịch chỉ ở lớp hiển thị. Khoá chuẩn không đổi, nên
        # SARIF/CSV và so sánh vẫn hoạt động.
        set_language("vi")
        from strix.report.writer import _SEVERITY_ORDER

        assert set(_SEVERITY_ORDER.keys()) == {"critical", "high", "medium", "low", "info"}


class TestIsVietnamese:
    def test_false_by_default(self) -> None:
        assert not is_vietnamese()

    def test_true_when_vi(self) -> None:
        set_language("vi")
        assert is_vietnamese()
