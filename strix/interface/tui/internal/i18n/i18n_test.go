package i18n

import (
	"os"
	"strings"
	"testing"
)

func withLang(t *testing.T, value string) {
	t.Helper()
	old, had := os.LookupEnv("STRIX_LANG")
	if err := os.Setenv("STRIX_LANG", value); err != nil {
		t.Fatalf("Setenv: %v", err)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv("STRIX_LANG", old)
		} else {
			_ = os.Unsetenv("STRIX_LANG")
		}
	})
}

func TestDefaultIsEnglish(t *testing.T) {
	withLang(t, "")
	if got := Language(); got != DefaultLanguage {
		t.Fatalf("Language() = %q, want %q", got, DefaultLanguage)
	}
}

func TestVietnameseVariants(t *testing.T) {
	for _, value := range []string{"vi", "VI", "vi-VN", "vi_VN", "Vi-Vn"} {
		withLang(t, value)
		if got := Language(); got != Vietnamese {
			t.Errorf("STRIX_LANG=%q: Language() = %q, want %q", value, got, Vietnamese)
		}
	}
}

func TestUnsupportedFallsBackToEnglish(t *testing.T) {
	for _, value := range []string{"fr", "de", "zh", "en-GB"} {
		withLang(t, value)
		if got := Language(); got != DefaultLanguage {
			t.Errorf("STRIX_LANG=%q: Language() = %q, want %q", value, got, DefaultLanguage)
		}
	}
}

func TestEnglishReturnsKeyUnchanged(t *testing.T) {
	withLang(t, "en")
	// Ràng buộc cốt lõi: chế độ mặc định không đổi một byte nào.
	for _, key := range []string{
		"Penetration test completed",
		"Vulnerability Report",
		"Executive Summary",
		"Description",
	} {
		if got := T(key); got != key {
			t.Errorf("T(%q) = %q, want unchanged", key, got)
		}
	}
}

func TestVietnameseTranslation(t *testing.T) {
	withLang(t, "vi")
	cases := map[string]string{
		"Penetration test completed": "Kiểm thử xâm nhập hoàn tất",
		"Vulnerability Report":       "Báo cáo lỗ hổng",
		"Description":                "Mô tả",
		"Evidence":                   "Bằng chứng",
		"Impact":                     "Tác động",
		"Remediation":                "Khắc phục",
		"Technical Analysis":         "Phân tích kỹ thuật",
	}
	for key, want := range cases {
		if got := T(key); got != want {
			t.Errorf("T(%q) = %q, want %q", key, got, want)
		}
	}
}

func TestUnknownKeyReturnsKeyInVietnamese(t *testing.T) {
	withLang(t, "vi")
	// Nhãn thiếu không được tạo chuỗi rỗng hay rác.
	const unknown = "Some string that has no translation"
	if got := T(unknown); got != unknown {
		t.Errorf("T(%q) = %q, want the key back", unknown, got)
	}
}

func TestVietnameseActive(t *testing.T) {
	withLang(t, "vi")
	if !VietnameseActive() {
		t.Error("VietnameseActive() = false, want true")
	}
	withLang(t, "en")
	if VietnameseActive() {
		t.Error("VietnameseActive() = true, want false")
	}
}

// TestTranslationsAreNonEmptyAndDistinct guards against a copy-paste that
// leaves an empty value (which would blank out UI text) and against an
// English key mapped to itself (which would be dead weight).
func TestTranslationsAreNonEmptyAndDistinct(t *testing.T) {
	for key, value := range translations {
		if strings.TrimSpace(value) == "" {
			t.Errorf("translation for %q is empty", key)
		}
		if value == key {
			t.Errorf("translation for %q is identical to the English key", key)
		}
	}
}

// TestVietnameseHasDiacritics catches ASCII-only entries, which violate the
// Vietnamese-with-diacritics requirement.
func TestVietnameseHasDiacritics(t *testing.T) {
	// Thuật ngữ quốc tế và từ tiếng Việt vốn không dấu được phép giữ nguyên.
	allowedNoDiacritics := map[string]bool{
		"CVSS Vector":            true,
		"Vector CVSS":            true,
		"Vector CVSS: ":          true,
		"CVSS theo khuyến cáo: ": true,
		"Điểm CVSS: ":            true,
		"CVSS Vector: ":          true,
		"Mã PoC":                 true,
		"PoC":                    true,
	}

	const diacritics = "ăâđêôơưáàảãạấầẩẫậắằẳẵặéèẻẽẹếềểễệíìỉĩịóòỏõọốồổỗộớờởỡợúùủũụứừửữựýỳỷỹỵ"
	for key, value := range translations {
		if allowedNoDiacritics[key] {
			continue
		}
		if !strings.ContainsAny(strings.ToLower(value), diacritics) {
			t.Errorf("translation for %q lacks Vietnamese diacritics: %q", key, value)
		}
	}
}

func TestTranslationCountNonTrivial(t *testing.T) {
	if got := TranslationCount(); got < 100 {
		t.Errorf("TranslationCount() = %d, expected at least 100 labels covered", got)
	}
}
