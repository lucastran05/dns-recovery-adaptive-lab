# Instructor guide và đáp án

## Tình huống

Key `legacy-ddns` từng dùng cho tự động hóa, bị lộ trong tình huống giả định nhưng chưa thu hồi. Lab cấp bản sao key cho attacker để tái hiện hậu quả; không mô phỏng bước đánh cắp key.

Scenario dùng nsupdate ký TSIG thật qua TCP 53, đổi A của portal thành 10.60.40.10 (TTL 300), xóa A của files. Máy rogue chạy HTTP không thu mật khẩu. Cache máy nhân viên được nạp kết quả sự cố ngay sau thao tác.

Đây là cập nhật trái phép theo nghiệp vụ nhưng được DNS cho phép bởi policy hiện tại, không phải cache poisoning bằng gói tin giả.

## Đáp án

| Phase | Đáp án cốt lõi |
|---|---|
| Chẩn đoán chuyển hướng | 10.60.40.10 |
| Truy vết key | legacy-ddns |
| Lập kế hoạch khôi phục | 10.60.20.20 |
| Thu hồi và khôi phục | CRCZ{DNS_RESTORED_LEGACY_UPDATE_REVOKED} |
| Xác minh | CRCZ{DNS_RESTORED_LEGACY_UPDATE_REVOKED} |

Flag cố định để nhập vào Adaptive task. Đây không phải cơ chế chống gian lận mật mã. Bảo vệ repository và runtime config khỏi học viên khi chấm độc lập.

## Policy

Policy ban đầu cấp riêng A records portal/files và TXT `_probe` cho legacy và recovery. Không cấp toàn zone và không cấp quyền NS/SOA.

Hardening bỏ các grant legacy, giữ key definition để request vẫn có chữ ký hợp lệ nhưng bị từ chối authorization bằng REFUSED. Recovery key được giữ để chứng minh hoạt động quản trị hợp lệ không bị vô hiệu hóa.

Nếu đổi bài thành xóa key definition, DNS có thể trả BADKEY; checker hiện tại cố ý không chấp nhận kết quả đó. Cần đổi rubric và tests tương ứng, không coi mọi lỗi là thành công.

## Chín điều kiện checker

1. Instructor đã khởi tạo incident thành công.
2. Authoritative portal có NOERROR, AA, đúng một IP chuẩn.
3. Authoritative files có NOERROR, AA, đúng một IP chuẩn.
4. Client cache portal đúng IP.
5. Client cache files đúng IP.
6. HTTP portal trả service_id `NORTHSTAR-INTRANET`.
7. HTTP files trả document_id `NS-HANDBOOK-2026`.
8. Probe bằng legacy key từ attacker nhận REFUSED rõ ràng.
9. Probe bằng recovery key vẫn thành công.

Timeout, API lỗi hoặc chữ ký sai không được tính là từ chối đúng policy. Checker chỉ đánh giá phạm vi bài lab, không chứng minh tất cả đường thay đổi DNS đều đã được bảo vệ.

## Bằng chứng

- Native log: `/var/cache/bind/dns-lab/updates.log` trên dns.
- Runtime actions: `/var/lib/dns-lab/actions.jsonl` trên node liên quan.
- Zone/journal: `/var/lib/bind/db.corp.test` và journal do named tạo.
- Policy: `/etc/bind/dns-lab-policy.conf`.
- HTTP identity từ portal, files và rogue.

BIND log luân phiên 3 file, 5 MB mỗi file. API evidence chỉ trả phần cuối để tránh tải quá lớn; instructor có thể lưu cả log. Log xác nhận key và nguồn network, không tự chứng minh danh tính cá nhân sử dụng key.

## Rubric đề xuất

20 điểm chẩn đoán, 20 điểm timeline và key, 15 điểm kế hoạch khôi phục, 25 điểm xử lý đúng, 15 điểm xác minh, 5 điểm báo cáo. Rubric được chấm riêng; chưa đồng bộ điểm này vào API Adaptive platform.

Ghi kèm variant, thời gian và mức hỗ trợ. Cùng đáp án cốt lõi nhưng yêu cầu lập luận khác; các phần lập luận do instructor đánh giá.

## Xử lý lỗi

| Triệu chứng | Kiểm tra |
|---|---|
| named không khởi động | `named-checkconf`, journal của service named, quyền bind với zone và logs |
| Scenario bị REFUSED ngay | Policy đã secure; reset trước lượt mới |
| TSIG BADSIG/BADKEY | Secrets trên dns và attacker/recovery không khớp hoặc key name sai |
| TSIG BADTIME | Đồng hồ các VM lệch; kiểm tra time sync của cloud |
| DNS đúng nhưng client sai | TTL/cache 127.0.0.1:5353; `dns-lab flush` |
| File service lỗi | files A record, route và dns-lab-web trên files |
| Probe legacy timeout | Routing/TCP53/Firewall, không kết luận policy đã an toàn |
| incident_initialized=false | Chạy start_scenario qua admin API, không chỉ chạy nsupdate thủ công |
| Workbench không truy cập | Cổng 8080, route vào management hoặc SSH tunnel |

Harden kiểm tra named config rồi rndc reconfig. Nếu validation/reload lỗi, runtime hoàn lại policy trước đó. Vẫn cần xem journal khi xử lý sự cố hệ thống thực.
