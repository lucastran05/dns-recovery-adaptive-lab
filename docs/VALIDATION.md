# Kiểm thử và phạm vi xác nhận

Ngày: 19/09/2026.

## Đã chạy

- Parse toàn bộ Python và YAML.
- Kiểm tra topology: 6 hosts, 1 router, địa chỉ thuộc subnet, groups khớp playbook.
- Kiểm tra secrets legacy/recovery khác nhau, tokens instructor/agent tách nhau.
- Kiểm tra 9 phases, 5 Training Phase, 15 task variants, quan hệ questionnaire và kích thước Decision Matrix.
- Chạy 10 tests Python, tất cả PASS:
  1. Parse DNS NOERROR/AA, NXDOMAIN và timeout.
  2. REFUSED khác BADKEY, lỗi chữ ký và timeout.
  3. nsupdate đúng key, server và record cố định.
  4. Policy rollback khi validation hoặc reload thất bại.
  5. Checker đạt khi đủ điều kiện; fail-closed khi thiếu dependency hoặc marker.
  6. Cache stale hoặc rogue HTTP identity không được cấp flag.
  7. Không gửi HTTP probe tới IP ngoài danh sách lab.
  8. Authentication HTTP và tách quyền instructor/học viên.
  9. HTTP dispatch thao tác diagnose/harden đúng backend.
  10. Agent từ chối request thiếu quyền hoặc reset bằng token học viên.

HTTP tests khởi động HTTP server thật trên loopback. Unit tests mock kết quả subprocess dig/nsupdate/named-checkconf/rndc và API backend. Chưa có test DNS packet exchange với daemon BIND thật trong môi trường tạo gói.

## Chưa chạy ở đây

- Ansible syntax-check/provisioning trên VM thật.
- BIND9 config validation thực bằng named-checkconf.
- TSIG dynamic update, dnsmasq cache và systemd trên data-plane thật.
- Import/release/adaptive simulator trên CyberRangeCZ của người dùng.

Các executable named, dig, nsupdate và ansible-playbook không có trong môi trường tạo gói. Kết quả local không thay thế xác nhận native.

## Gate trên sandbox

```bash
ansible-playbook -i inventory.ini provisioning/playbook.yml --syntax-check
ansible-playbook -i inventory.ini provisioning/playbook.yml
ansible-playbook -i inventory.ini tools/preflight.yml
ansible-playbook -i inventory.ini tools/acceptance.yml
```

Acceptance tự kiểm tra chuỗi reset → gây sự cố → checker chưa đạt → thu hồi key → vẫn chưa đạt → khôi phục → flush → checker đạt. Dùng một sandbox dùng thử; playbook để lại hệ thống đã phục hồi và harden.

Trước giao học viên:

```bash
ansible-playbook -i inventory.ini tools/reset.yml
ansible-playbook -i inventory.ini tools/start_scenario.yml
```

Ngoài playbook, instructor cần kiểm tra native log chứa key/source đúng, simulator chọn variants phù hợp và truy cập bằng tài khoản học viên không lộ secrets.
