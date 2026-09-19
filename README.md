# Northstar DNS Recovery · Adaptive CyberRange Lab

**Bài thực hành độc lập về điều tra và khôi phục DNS doanh nghiệp.** Không dùng SIEM, Port Scan hay cơ sở dữ liệu bán hàng của bài mẫu.

Northstar Logistics có cổng nhân viên và kho tài liệu nội bộ. Một TSIG key cũ bị lộ nhưng vẫn có quyền dynamic update. Trong sandbox, nguồn không được doanh nghiệp cho phép dùng key này để chuyển `portal.corp.test` sang website giả lập và xóa A record của `files.corp.test`. Học viên phải điều tra, khôi phục và thu hồi quyền key mà vẫn giữ hoạt động cập nhật hợp lệ.

## Điểm bắt đầu

1. Đọc `docs/DEPLOYMENT.md`, chỉnh tên image/flavor cho cloud.
2. Đưa repository lên Git, tạo Sandbox Definition và provision.
3. Import `training.json` vào **Adaptive Training Definition**.
4. Instructor chạy `tools/start_scenario.yml` trước khi phát bài.
5. Học viên bắt đầu từ console `admin` và `dns-lab diagnose`.

## Thành phần

| Thành phần | IP | Vai trò |
|---|---|---|
| admin | 10.60.10.10 | Console học viên, workbench HTTP :8080 và checker |
| dns | 10.60.20.53 | BIND9 authoritative DNS, TSIG update policy |
| portal | 10.60.20.10 | Cổng nội bộ HTTP :80 |
| files | 10.60.20.20 | Kho tài liệu mẫu HTTP :80 |
| workstation | 10.60.30.10 | Máy nhân viên với dnsmasq cache 127.0.0.1:5353 |
| attacker | 10.60.40.10 | Nguồn cập nhật bằng legacy key và website giả lập |
| router | .1 trên mỗi subnet | Routing giữa 4 subnet do CyberRangeCZ dựng |

Zone chỉ tồn tại trong sandbox: `corp.test.`. `files` là HTTP file service, không phải SMB hoặc Active Directory. Trang giả không thu thập mật khẩu.

## Cấu trúc

- `topology.yml`: 6 hosts, 1 router, 4 subnet và inventory groups.
- `training.json`: 9 phases tổng cộng, 5 Training Phase với 15 variants.
- `provisioning/playbook.yml`: cấu hình toàn bộ services.
- `provisioning/group_vars/all.yml`: URL/IP, credentials, TSIG secrets.
- `provisioning/roles/`: common, dns, client, attacker, admin, web.
- `provisioning/templates/`: BIND config, zone, TSIG keys, policy và systemd.
- `provisioning/files/dns_lab.py`: API có thao tác cố định, không nhận shell command từ client.
- `provisioning/files/dns-lab.py`: CLI cho học viên.
- `tools/`: preflight, kích hoạt sự cố, acceptance, reset, kiểm tra cấu trúc và đổi secrets.
- `tests/`: unit tests và HTTP integration tests.
- `docs/`: hướng dẫn triển khai, học viên, instructor, adaptive và báo cáo.

## Adaptive và mục tiêu

Thời lượng 100 phút. Mỗi phase có ba variants: nâng cao, tiêu chuẩn, cơ bản. Cùng mục tiêu và đáp án cốt lõi, khác mức hướng dẫn và yêu cầu phân tích. Decision Matrix dựa vào questionnaire và kết quả phase trước. Việc chọn variant do CyberRangeCZ thực hiện; không thay topology động.

Các phase: chẩn đoán chuyển hướng, truy vết TSIG key, lập kế hoạch khôi phục, thu hồi quyền và khôi phục, xác minh chống tái diễn.

## Kiểm tra local

```bash
python3 -m pip install PyYAML
python3 tools/validate.py
python3 -m unittest discover -s tests -v
```

Test local kiểm tra parser DNS, phân biệt REFUSED với timeout, rollback policy, điều kiện checker và authentication HTTP. **Các lệnh BIND/dig/nsupdate được mock trong unit tests.** Chưa chứng nhận triển khai thật từ kết quả test này. Xem `docs/VALIDATION.md`.

Để kiểm tra native trên sandbox sau provisioning:

```bash
ansible-playbook -i inventory.ini tools/preflight.yml
ansible-playbook -i inventory.ini tools/acceptance.yml
```

Acceptance chủ động tạo và sửa sự cố trong sandbox; chạy trên sandbox dùng thử. Sau acceptance, reset và kích hoạt lại sự cố trước khi giao học viên.

## Truy cập mặc định

- Console admin và workbench: `analyst` / `Analyst-DNS-2026!`.
- Workbench: `http://10.60.10.10:8080` khi có route vào sandbox.
- CLI: `dns-lab diagnose`, `dns-lab evidence`, `dns-lab check`.

TSIG secrets và API tokens được tạo riêng khi xây dựng gói. Instructor có thể đổi bằng `tools/rotate_secrets.py` trước provisioning. Repository chứa đáp án và secrets phục vụ triển khai, không phát nguyên bộ cho học viên trong kỳ đánh giá độc lập.

## Phạm vi thực tế

BIND9 phục vụ DNS thật; `nsupdate` gửi RFC 2136 update được ký TSIG; dnsmasq có cache thật; HTTP identity được lấy từ node mà DNS trả về. Workbench chỉ điều phối các thao tác đã định nghĩa.

Bài mô phỏng **lạm dụng key bị lộ**, không khai thác CVE hoặc giả mạo gói DNS. Thu hồi quyền legacy key trong update policy khiến key được nhận diện nhưng không được phép cập nhật. Recovery key vẫn được cấp quyền giới hạn đúng tên và loại bản ghi.

Chưa có packet capture dashboard, TLS nội bộ, DHCP, DNSSEC, DNS secondary hoặc automatic failover. DNS cache học tập dùng port 5353 riêng, không sửa `/etc/resolv.conf` của VM để tránh làm hỏng provisioning. Native query qua `dig` và client probe sử dụng cache này một cách tường minh.

Gói là mã nguồn lab, không gồm disk images và không cài nền tảng CyberRangeCZ. Cần kiểm tra image/flavor, inventory, schema import và routing trên bản cài thực tế.
