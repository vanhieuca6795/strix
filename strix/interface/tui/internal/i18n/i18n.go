// Package i18n cung cấp nhãn hiển thị đa ngữ cho TUI của Strix.
//
// Thiết kế: KHOÁ CHÍNH LÀ CHUỖI TIẾNG ANH. Nhờ vậy:
//   - Mặc định (không đặt STRIX_LANG) giữ nguyên hành vi cũ, không đổi một byte
//     nào trong output, nên test hiện có không vỡ.
//   - Thiếu bản dịch thì rơi về chính khoá = tiếng Anh; TUI không bao giờ hiện
//     chuỗi rỗng hay rác.
//   - Việc thay thế tại chỗ rất cơ học: "Foo" -> i18n.T("Foo").
//
// KHÔNG dịch (cố ý bỏ khỏi bảng): định danh kỹ thuật và giao thức như
// "REQUEST", "DIRECT", "DOMAIN", "STRIX_TUI_FD", "Agent" (thuật ngữ trong
// ngữ cảnh này), và thông báo lỗi giao thức nội bộ.
package i18n

import (
	"os"
	"strings"
)

// DefaultLanguage là ngôn ngữ khi không có cấu hình nào.
const DefaultLanguage = "en"

// Vietnamese là mã ngôn ngữ được hỗ trợ ngoài tiếng Anh.
const Vietnamese = "vi"

// translations ánh xạ chuỗi tiếng Anh sang bản dịch tiếng Việt có dấu.
var translations = map[string]string{
	// --- Tiêu đề mục báo cáo / lỗ hổng ---
	"Vulnerability Report":         "Báo cáo lỗ hổng",
	"Vulnerability Report Updated": "Báo cáo lỗ hổng đã cập nhật",
	"Dependency (SCA) Report":      "Báo cáo phụ thuộc (SCA)",
	"Description":                  "Mô tả",
	"Impact":                       "Tác động",
	"Evidence":                     "Bằng chứng",
	"Counterevidence":              "Chứng cứ phản bác",
	"Technical Analysis":           "Phân tích kỹ thuật",
	"Remediation":                  "Khắc phục",
	"Assumptions":                  "Giả định",
	"PoC Code":                     "Mã PoC",
	"PoC Description":              "Mô tả PoC",
	"Code Locations":               "Vị trí mã nguồn",
	"Fix Verification":             "Kiểm chứng bản vá",
	"Fix Effort":                   "Công sức khắc phục",
	"Confidence":                   "Độ tin cậy",
	"Severity":                     "Mức độ",
	"Severity Would Change If":     "Điều kiện làm thay đổi mức độ",
	"Assumptions: ":                "Giả định: ",

	// --- Nhãn trường ---
	"Title":             "Tiêu đề",
	"Title: ":           "Tiêu đề: ",
	"Target":            "Mục tiêu",
	"Targets":           "Các mục tiêu",
	"Endpoint":          "Điểm cuối",
	"Method":            "Phương thức",
	"Found":             "Phát hiện lúc",
	"Package":           "Gói",
	"Package: ":         "Gói: ",
	"Ecosystem":         "Hệ sinh thái",
	"Installed Version": "Phiên bản đang cài",
	"Fixed Version":     "Phiên bản đã vá",
	"Introduced By":     "Đưa vào bởi",
	"Dependency Chain":  "Chuỗi phụ thuộc",
	"Installed: ":       "Đang cài: ",
	"Fixed: ":           "Đã vá: ",
	"Severity: ":        "Mức độ: ",
	"CVSS Score: ":      "Điểm CVSS: ",
	"CVSS Vector":       "Vector CVSS",
	"CVSS Vector: ":     "Vector CVSS: ",
	"Advisory CVSS: ":   "CVSS theo khuyến cáo: ",
	"Confidence: ":      "Độ tin cậy: ",
	"Output:":           "Kết quả:",
	"Reason":            "Lý do",
	"Usage evidence: ":  "Bằng chứng sử dụng: ",

	// --- Trạng thái / tiến trình ---
	"Penetration test completed":    "Kiểm thử xâm nhập hoàn tất",
	"Scan completed":                "Quét hoàn tất",
	"Scan failed":                   "Quét thất bại",
	"Scan stopped":                  "Quét đã dừng",
	"Agent completed":               "Agent hoàn tất",
	"Agent failed":                  "Agent thất bại",
	"Agent stopped":                 "Agent đã dừng",
	"Budget limit reached":          "Đã chạm hạn mức ngân sách",
	"Thinking":                      "Đang suy luận",
	"Thinking...":                   "Đang suy luận...",
	"Processing...":                 "Đang xử lý...",
	"Loading...":                    "Đang tải...",
	"Creating...":                   "Đang tạo...",
	"Creating report...":            "Đang tạo báo cáo...",
	"Creating dependency report...": "Đang tạo báo cáo phụ thuộc...",
	"Capturing...":                  "Đang ghi nhận...",
	"Completing task...":            "Đang hoàn tất tác vụ...",
	"Recording...":                  "Đang ghi...",
	"Saving...":                     "Đang lưu...",
	"Removing...":                   "Đang xoá...",
	"Reopening...":                  "Đang mở lại...",
	"Marking done...":               "Đang đánh dấu xong...",
	"Updating...":                   "Đang cập nhật...",
	"Updating report...":            "Đang cập nhật báo cáo...",
	"Amending...":                   "Đang bổ sung...",
	"Generating final report...":    "Đang tạo báo cáo cuối...",
	"Starting agent...":             "Đang khởi động agent...",
	"Starting Strix Agent":          "Đang khởi động Strix Agent",
	"Preparing scan...":             "Đang chuẩn bị quét...",
	"Initializing":                  "Đang khởi tạo",
	"Searching the web...":          "Đang tìm trên web...",
	"Listing MCP servers":           "Đang liệt kê máy chủ MCP",
	"Inspecting MCP server ":        "Đang kiểm tra máy chủ MCP ",
	"Backend disconnected: ":        "Mất kết nối backend: ",

	// --- Bảng điều khiển / tương tác ---
	"What should Strix test?":                 "Strix nên kiểm thử gì?",
	"Describe what to test, or name a target": "Mô tả cần kiểm thử, hoặc nêu mục tiêu",
	"Send a message":                          "Gửi tin nhắn",
	"Send message to resume":                  "Gửi tin nhắn để tiếp tục",
	"Quit Strix?":                             "Thoát Strix?",
	"Strix Help":                              "Trợ giúp Strix",
	"Open-source AI hackers for your apps":    "AI hacker mã nguồn mở cho ứng dụng của bạn",
	"Welcome to ":                             "Chào mừng đến ",
	"Hello, I am Strix":                       "Xin chào, tôi là Strix",
	"Welcome to Strix":                        "Chào mừng đến Strix",
	"Executive Summary":                       "Tóm tắt tổng quan",
	"Methodology":                             "Phương pháp",
	"Recommendations":                         "Khuyến nghị",
	"Threat Model":                            "Mô hình mối đe dọa",
	"Threat Model Saved":                      "Đã lưu mô hình mối đe dọa",
	"Threat Model Amended":                    "Đã bổ sung mô hình mối đe dọa",
	"Coverage":                                "Độ phủ",
	"Coverage Recorded":                       "Đã ghi độ phủ",
	"Coverage Updated":                        "Đã cập nhật độ phủ",
	"Todos":                                   "Việc cần làm",
	"Todo Completed":                          "Đã xong việc",
	"Todo Removed":                            "Đã xoá việc",
	"Todo Reopened":                           "Đã mở lại việc",
	"Todo Updated":                            "Đã cập nhật việc",
	"Report":                                  "Báo cáo",
	"Mount":                                   "Điểm gắn",
	"Command failed":                          "Lệnh thất bại",
	"Copied to clipboard":                     "Đã sao chép",
	"Copied!":                                 "Đã sao chép!",
	"Copy failed":                             "Sao chép thất bại",
	"Copy failed: ":                           "Sao chép thất bại: ",
	"ChatGPT subscription":                    "Gói đăng ký ChatGPT",
	"In use":                                  "Đang dùng",

	// --- Thông báo rỗng / lỗi hiển thị ---
	"No notes":                                "Không có ghi chú",
	"No reports filed yet":                    "Chưa có báo cáo nào",
	"No todos":                                "Không có việc cần làm",
	"No surfaces recorded yet":                "Chưa ghi bề mặt nào",
	"No surfaces match this filter":           "Không có bề mặt nào khớp bộ lọc",
	"No model derived for this target yet":    "Chưa có mô hình cho mục tiêu này",
	"No agent is available":                   "Không có agent nào",
	"No description provided.":                "Không có mô tả.",
	"Untitled Vulnerability":                  "Lỗ hổng chưa đặt tên",
	"Unknown Vulnerability":                   "Lỗ hổng không rõ",
	"Unable to list coverage":                 "Không liệt kê được độ phủ",
	"Unable to list todos":                    "Không liệt kê được việc cần làm",
	"Unable to read threat model":             "Không đọc được mô hình mối đe dọa",
	"Failed to create todo":                   "Tạo việc thất bại",
	"Failed to mark todo done":                "Đánh dấu xong thất bại",
	"Failed to remove todo":                   "Xoá việc thất bại",
	"Failed to reopen todo":                   "Mở lại việc thất bại",
	"Failed to update todo":                   "Cập nhật việc thất bại",
	"Failed to record coverage":               "Ghi độ phủ thất bại",
	"Failed to update coverage":               "Cập nhật độ phủ thất bại",
	"Failed to save threat model":             "Lưu mô hình mối đe dọa thất bại",
	"Failed to amend threat model":            "Bổ sung mô hình mối đe dọa thất bại",
	"Report could not be persisted.":          "Không lưu được báo cáo.",
	"Report was not created.":                 "Báo cáo chưa được tạo.",
	"Viewer UI not built":                     "Giao diện xem chưa được dựng",
	"Viewer failed to start":                  "Không khởi động được giao diện xem",
	"Unknown collection: ":                    "Bộ sưu tập không rõ: ",
	"Protocol mismatch: backend=%d client=%d": "Sai khớp giao thức: backend=%d client=%d",
}

// Language trả về mã ngôn ngữ hiện hành, đọc từ biến môi trường STRIX_LANG.
// Chấp nhận "vi", "vi-VN", "vi_VN". Giá trị không hỗ trợ rơi về tiếng Anh.
func Language() string {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("STRIX_LANG")))
	if i := strings.IndexAny(raw, "_-"); i >= 0 {
		raw = raw[:i]
	}
	if raw == Vietnamese {
		return Vietnamese
	}
	return DefaultLanguage
}

// T dịch một chuỗi hiển thị. Khoá là chính chuỗi tiếng Anh.
//
// Thiếu bản dịch, hoặc ngôn ngữ là tiếng Anh, thì trả lại nguyên khoá — nên
// hành vi mặc định không bao giờ đổi và không có chuỗi nào biến mất.
func T(english string) string {
	if Language() != Vietnamese {
		return english
	}
	if translated, ok := translations[english]; ok && translated != "" {
		return translated
	}
	return english
}

// Vietnamese reports whether the active language is Vietnamese.
func VietnameseActive() bool {
	return Language() == Vietnamese
}

// TranslationCount trả về số nhãn đã có bản dịch. Dùng cho chẩn đoán và test.
func TranslationCount() int {
	return len(translations)
}
