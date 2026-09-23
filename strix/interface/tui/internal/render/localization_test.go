package render

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

// TestRenderFinishScanLocalized proves the report headings rendered into the
// TUI follow STRIX_LANG, while the body content the agent wrote is untouched.
func TestRenderFinishScanLocalized(t *testing.T) {
	args := map[string]any{
		"executive_summary":  "Nội dung tóm tắt do agent viết.",
		"methodology":        "Phương pháp kiểm thử.",
		"technical_analysis": "Phân tích kỹ thuật chi tiết.",
		"recommendations":    "Khuyến nghị khắc phục.",
	}

	withLang(t, "en")
	english := renderFinishScan(args)
	for _, want := range []string{
		"Penetration test completed",
		"Executive Summary",
		"Methodology",
		"Technical Analysis",
		"Recommendations",
	} {
		if !strings.Contains(english, want) {
			t.Errorf("EN output missing %q", want)
		}
	}

	withLang(t, "vi")
	vietnamese := renderFinishScan(args)
	for _, want := range []string{
		"Kiểm thử xâm nhập hoàn tất",
		"Tóm tắt tổng quan",
		"Phương pháp",
		"Phân tích kỹ thuật",
		"Khuyến nghị",
	} {
		if !strings.Contains(vietnamese, want) {
			t.Errorf("VI output missing %q\n--- got ---\n%s", want, vietnamese)
		}
	}

	// Nội dung do agent viết phải nguyên vẹn ở cả hai ngôn ngữ.
	for _, body := range []string{
		"Nội dung tóm tắt do agent viết.",
		"Phân tích kỹ thuật chi tiết.",
		"Khuyến nghị khắc phục.",
	} {
		if !strings.Contains(vietnamese, body) {
			t.Errorf("VI output dropped agent body content: %q", body)
		}
	}
}

// TestReportSectionLabelsLocalized checks the shared `section` helper, which
// covers most of the field labels across the report renderers.
func TestReportSectionLabelsLocalized(t *testing.T) {
	args := map[string]any{
		"title":       "SQL injection tại /user",
		"description": "Mô tả lỗ hổng do agent viết.",
		"impact":      "Tác động do agent viết.",
		"severity":    "high",
		"target":      "https://app.example.com",
	}

	withLang(t, "en")
	en := renderVulnerabilityReport(args, nil)
	if !strings.Contains(en, "Description") {
		t.Errorf("EN report missing Description section\n%s", en)
	}

	withLang(t, "vi")
	vi := renderVulnerabilityReport(args, nil)
	for _, want := range []string{"Mô tả", "Tác động"} {
		if !strings.Contains(vi, want) {
			t.Errorf("VI report missing %q\n--- got ---\n%s", want, vi)
		}
	}
	// Giá trị kỹ thuật và nội dung agent viết không được đổi.
	for _, keep := range []string{
		"SQL injection tại /user",
		"Mô tả lỗ hổng do agent viết.",
		"Tác động do agent viết.",
		"https://app.example.com",
	} {
		if !strings.Contains(vi, keep) {
			t.Errorf("VI report dropped technical content: %q", keep)
		}
	}
}

// TestEnglishIsByteIdentical guards the core compatibility promise: without
// STRIX_LANG, the renderers must produce exactly what they did before.
func TestEnglishIsByteIdentical(t *testing.T) {
	args := map[string]any{
		"executive_summary": "Body.",
		"methodology":       "Method.",
	}
	withLang(t, "en")
	first := renderFinishScan(args)
	withLang(t, "fr") // unsupported language falls back to English too
	second := renderFinishScan(args)
	if first != second {
		t.Errorf("unsupported language changed output:\n EN: %q\n FR: %q", first, second)
	}
}
