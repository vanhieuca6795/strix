---
name: vietnam_web_targets
description: Kỹ thuật kiểm thử cho website Việt Nam — CMS nội địa (InLight, NukeViet, Zimbra), cổng hành chính, và các cạm bẫy thường gặp. Dùng khi target là tên miền .vn hoặc hạ tầng do đơn vị Việt Nam vận hành.
---

# Kiểm thử website và hạ tầng Việt Nam

Kỹ năng này bổ sung ngữ cảnh đặc thù cho target `.vn`, máy chủ đặt tại Việt Nam,
hoặc hệ thống do đơn vị nhà nước/doanh nghiệp Việt Nam vận hành.

## 1. CMS và nền tảng nội địa thường gặp

Nhận diện sớm để tra CVE đúng chỗ thay vì đoán mò:

| Nền tảng | Dấu hiệu nhận biết | Hướng kiểm thử |
|---|---|---|
| **InLight Framework** | `X-Powered-By`, cookie `inlight_session`, cấu trúc `/admin/auth/login` | Tra CVE công bố; kiểm tra endpoint `/oauth/`, `/tags/`, `/search/` cho injection |
| **NukeViet** | `nv_` prefix trong cookie/URL, `/includes/`, `/modules/` | LFI qua tham số module, SQLi ở `q=`; kiểm tra `/admin/` mặc định |
| **Zimbra** | `/service/`, `/zimbra/`, header `ZM_` | CVE đã biết ở webmail, SSRF nội bộ, xem header `X-Zimbra-*` |
| **Viettel / VNPT portal** | Trang đăng nhập SSO tập trung | Kiểm tra redirect_uri, OAuth flow, subdomain wildcard |
| **WordPress + plugin VN** | `/wp-content/`, plugin Việt tự viết | Plugin nội địa ít cập nhật — tra version chính xác trước khi thử |

**Luôn hỏi trước:** phiên bản CMS chính xác. Với CMS nội địa, tài liệu công khai
rất ít — đôi khi phải suy từ ngày build trong asset tĩnh.

## 2. Cổng thông tin hành chính công

Các cổng `.gov.vn` thường có đặc điểm:

- **Basic Auth trên port phụ** (8080, 8081, 8443) bảo vệ khu vực quản trị. Ghi nhận
  là phát hiện, không brute-force khi chưa được uỷ quyền bằng văn bản.
- **Chứng thư SSL dùng chung**: một wildcard `*.domain.vn` phủ nhiều hệ thống con.
  Sai cấu hình trên một subdomain có thể ảnh hưởng toàn bộ.
- **Chia sẻ hạ tầng**: nhiều cổng cùng dùng một máy chủ. Xác định ranh giới phạm vi
  được phép trước khi mở rộng — đụng hệ thống ngoài phạm vi là vấn đề pháp lý.
- **Header bảo mật thường thiếu** `Content-Security-Policy`. Ghi nhận ở mức thông tin
  nếu không khai thác được.

## 3. Cạm bẫy cần tránh

Những điều dễ gây sai sót hoặc rắc rối pháp lý khi làm với target Việt Nam:

- **CDN che IP thật**: header `X-Cache: HIT` nghĩa là đang nói chuyện với CDN, không
  phải máy chủ gốc. Đừng kết luận về máy chủ từ response của CDN.
- **Nhiều hệ thống không thuộc phạm vi cùng dải IP**: kiểm tra kỹ `WHOIS`/`ASN` trước
  khi quét mở rộng.
- **Trang lỗi tiếng Việt lộ đường dẫn nội bộ**: đôi khi tiết lộ cấu trúc thư mục và
  stack. Đọc kỹ thay vì bỏ qua.
- **Đừng dịch payload**: giữ nguyên payload khai thác bằng tiếng Anh/ASCII. Chỉ báo
  cáo và bằng chứng mới cần tiếng Việt.

## 4. Báo cáo bằng tiếng Việt

Khi viết `create_vulnerability_report` cho khách hàng Việt Nam:

- **Tiêu đề và mô tả**: tiếng Việt có dấu đầy đủ, văn phong trang trọng.
- **Thuật ngữ kỹ thuật**: giữ nguyên tiếng Anh (SQL injection, XSS, SSRF, IDOR) —
  không dịch, vì bản dịch làm mất độ chính xác và khó tra cứu.
- **`poc_script_code`**: giữ nguyên code gốc, không chú thích tiếng Việt bên trong
  payload — có thể phá cú pháp.
- **`evidence`**: trích dẫn output thật, giữ nguyên định dạng gốc. Có thể thêm một
  câu diễn giải tiếng Việt phía trên khối trích dẫn.
- **Mức độ**: dùng `nghiêm trọng` / `cao` / `trung bình` / `thấp` / `thông tin` khi
  trình bày, nhưng trường `severity` của report vẫn để chuẩn gốc để SARIF/CVSS đúng.

## 5. Bằng chứng theo chuẩn kiểm định

Để báo cáo đứng vững khi bị chất vấn (điều thường gặp ở khối nhà nước):

- Mỗi phát hiện phải có **một lát cắt output thật** làm bằng chứng, không diễn giải
  lại bằng lời.
- Ghi **thời điểm** (UTC) và **địa chỉ IP nguồn** của lần kiểm thử.
- Với phát hiện không khai thác được, ghi rõ **đã kiểm gì** và **kết luận gì** —
  đây là phần chứng minh độ phủ, có giá trị ngang với phát hiện.
- Nêu rõ **giả định** khai thác (cần credential nào, cần ở mạng nội bộ hay không).
