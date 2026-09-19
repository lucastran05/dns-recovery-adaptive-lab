# Phiếu thực hành: Northstar DNS Recovery

Nhân viên báo cổng nội bộ hiện trang không đúng, còn tài liệu công ty không truy cập được. Hãy điều tra bằng dữ liệu DNS và log, tránh kết luận chỉ từ giao diện trình duyệt.

## Hồ sơ tài sản được phê duyệt

| Tên | IP chuẩn | Công dụng |
|---|---|---|
| ns.corp.test | 10.60.20.53 | DNS authoritative |
| portal.corp.test | 10.60.20.10 | Cổng nhân viên |
| files.corp.test | 10.60.20.20 | Tài liệu nội bộ |

## Công cụ

| Lệnh | Kết quả |
|---|---|
| `dns-lab diagnose` | Truy vấn trực tiếp DNS authoritative, rcode và cờ AA |
| `dns-lab client` | Truy vấn cache máy nhân viên và kiểm tra HTTP identity |
| `dns-lab evidence` | 150 dòng cuối của native BIND update/security log |
| `dns-lab policy` | Update policy hiện tại, không hiển thị secret |
| `dns-lab harden` | Thu hồi grant của key cũ; giữ key khôi phục |
| `dns-lab restore` | Khôi phục A records bằng recovery TSIG key |
| `dns-lab flush` | Xóa cache học tập trên máy nhân viên |
| `dns-lab check` | Chạy kiểm tra kết quả |

Có thể truy vấn độc lập từ admin:

```bash
dig @10.60.20.53 portal.corp.test A
dig @10.60.20.53 files.corp.test A
dig @10.60.20.53 corp.test SOA
```

Các phần quan trọng: `status` là mã kết quả; cờ `aa` chỉ câu trả lời authoritative; phần ANSWER chứa TTL và IP. `NXDOMAIN` khác timeout và khác `NOERROR` không có A record.

## Quy trình

1. Đọc nhiệm vụ variant được giao và lưu kết quả ban đầu.
2. So sánh bản ghi thực tế với hồ sơ tài sản.
3. Đối chiếu log cập nhật với policy để xác định quyền bị lạm dụng.
4. Lập kế hoạch thu hồi quyền, khôi phục record và xử lý cache.
5. Thực hiện thao tác ứng phó; lưu kết quả trước/sau.
6. Chạy checker và hoàn thiện báo cáo bằng chứng.

Checker tạo/thay một TXT record `_probe.corp.test` để kiểm tra quyền cập nhật. Nó không sửa hai bản ghi nghiệp vụ. Đạt khi DNS và cache đúng, dịch vụ chuẩn hoạt động, key cũ nhận REFUSED và key hợp lệ vẫn cập nhật được.

Cache có TTL thật. Kết quả cũ có thể tự hết hạn; khi đó flush không còn bắt buộc để checker đạt. Hãy giải thích TTL thay vì coi mọi khác biệt authoritative/client là một lần tấn công mới.

## Giới hạn quyền

Tài khoản analyst không có sudo. Workbench cung cấp các thao tác quản trị cố định của bài học. Không có chức năng gửi shell command tùy ý. Instructor quản lý VM, keys và reset.
