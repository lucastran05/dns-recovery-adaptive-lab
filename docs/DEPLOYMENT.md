# Triển khai lên CyberRangeCZ

## 1. Điều kiện

- CyberRangeCZ có Sandbox service, Adaptive Training service và cloud provider đã hoạt động.
- Image Ubuntu có Python 3.8+; router Debian theo topology. Tên image/flavor phải có thật trong cloud.
- 7 VM theo topology; tài nguyên thực tế tùy flavor, không suy ra RAM từ tên `standard.small`.
- Trong provisioning, VM truy cập được package repository hoặc đã có sẵn Python, BIND9, dnsutils, dnsmasq-base và curl.
- Data-plane của sandbox được cô lập; đường quản trị do nền tảng kiểm soát.

Giữ tên image từ mẫu để dễ thay: `ubuntu-focal-x86_64`, `debian-11`. Có thể đổi sang image Ubuntu mới hơn nếu môi trường đã chuẩn bị. Mặc định service BIND là `named`; nếu image dùng tên khác, sửa `bind_service` trong group_vars.

## 2. Chuẩn bị repository

Giải nén. Đặt nội dung thư mục `dns-recovery-adaptive-lab` tại root repository Git, để `topology.yml` và `provisioning/playbook.yml` nằm đúng vị trí. Commit và push lên Git server mà platform truy cập được.

Tạo Sandbox Definition bằng repository URL và revision, tạo Pool rồi allocate sandbox. Không upload file ZIP vào trường URL repository. Chờ mọi play provisioning thành công.

Topology chịu trách nhiệm máy và mạng; Ansible cài dịch vụ. Router do nền tảng cấu hình, playbook không viết lại routing hoặc Firewall nền tảng.

## 3. Cấu hình trước provisioning

- `topology.yml`: image, flavor và IP/data networks.
- `provisioning/group_vars/all.yml`: URL/API và địa chỉ dịch vụ phải khớp topology.
- `training.json`: đáp án địa chỉ nếu đổi IP, nội dung access nếu đổi tài khoản.

Giữ zone `corp.test.` cho gói này. Nếu đổi zone, cần cập nhật templates, training, docs và các giá trị tên; không chỉ đổi một dòng.

Đổi secrets trước triển khai:

```bash
python3 -m pip install PyYAML
python3 tools/rotate_secrets.py
```

Yêu cầu lệnh `openssl` trên máy instructor. Script cập nhật student password hash, TSIG secrets, API tokens và access content trong training. Sau đó đọc credential từ group_vars và bảo vệ repository. Không dùng secrets này ngoài lab.

## 4. Với các VM đã cấp phát riêng

Copy `inventory.example.ini` thành `inventory.ini`, sửa IP quản trị 192.0.2.x và private key. Các VM phải có sẵn IP data-plane/route đúng topology. Ansible không tạo VM hay NIC từ file inventory.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
ansible-playbook -i inventory.ini provisioning/playbook.yml --syntax-check
ansible-playbook -i inventory.ini provisioning/playbook.yml
ansible-playbook -i inventory.ini tools/preflight.yml
```

Trong CyberRangeCZ dùng inventory/quyền quản trị platform cung cấp. Không dùng tài khoản analyst để provision và không tắt SSH host-key checking.

## 5. Kiểm tra services

- dns: `named`, `dns-lab-agent`, UDP/TCP 53 và API 9090.
- workstation: `dns-lab-cache`, `dns-lab-agent`; cache loopback port 5353.
- attacker: `dns-lab-agent`, `dns-lab-web`.
- portal/files: `dns-lab-web`.
- admin: `dns-lab-agent`, workbench 8080.

Trên dns, `named-checkconf` phải thành công. Zone dùng `/var/lib/bind/db.corp.test`; BIND quản lý journal khi dynamic update. Không sửa trực tiếp file zone đang hoạt động để hoàn thành bài; dùng recovery update.

## 6. Chạy native acceptance

Trên một sandbox thử nghiệm:

```bash
ansible-playbook -i inventory.ini tools/acceptance.yml
```

Playbook reset, gây sự cố thật, kiểm tra chưa đạt, thu hồi legacy key, kiểm tra vẫn chưa đạt, khôi phục, xóa cache và yêu cầu checker đạt. Đây là test thực, thay đổi trạng thái sandbox. Nếu fail, đọc log và output; không coi YAML parse là đủ.

## 7. Chuẩn bị cho học viên

```bash
ansible-playbook -i inventory.ini tools/reset.yml
ansible-playbook -i inventory.ini tools/start_scenario.yml
```

Kích hoạt scenario sẽ:

1. Dùng legacy TSIG key trên attacker sửa portal về IP rogue và xóa files A.
2. Xóa cache học tập cũ rồi truy vấn để nạp kết quả sự cố.
3. Chỉ báo ready khi portal trả rogue IP và files trả NXDOMAIN.
4. Ghi marker khởi tạo ở admin để checker không cấp flag cho lab chưa chạy scenario.

Không chạy scenario tự động lặp vô hạn. Sau hardening, lệnh scenario sẽ bị REFUSED; đây là hành vi mong đợi. Reset chỉ dành instructor để chuẩn bị lượt tiếp theo.

## 8. Import adaptive

Vào **Adaptive Training Definition**, upload `training.json`. Xác minh 9 phases, 5 Training Phase, 15 tasks, quan hệ questionnaire và Decision Matrix. Dùng simulator với hai hoặc nhiều hồ sơ học viên trước Release.

Sau Release, tạo Training Instance và gắn Pool theo workflow platform. File bám mẫu adaptive chính thức; cần đối chiếu validator của bản cài. Không import vào Linear Training Definition.

## 9. Truy cập workbench

Mở console node admin và đăng nhập analyst. CLI không cần trình duyệt:

```bash
dns-lab diagnose
dns-lab client
dns-lab evidence
```

Trình duyệt truy cập `http://10.60.10.10:8080` nếu PC có route vào sandbox. Nếu không, dùng SSH config do platform cấp để forward:

```bash
ssh -F /path/to/generated-config -L 18080:10.60.10.10:8080 <admin-host-alias>
```

Mở `http://127.0.0.1:18080`. Thay alias theo file thực tế, không mặc định platform có alias giống nhau giữa các sandbox.

## 10. Reset và giữ bằng chứng

`tools/reset.yml` khôi phục policy dễ bị lạm dụng, sửa lại bản ghi chuẩn, flush cache và xóa marker scenario. Nó giữ native BIND logs và lịch sử thao tác. Chạy start_scenario để bắt đầu lượt mới; tạo sandbox mới nếu cần lịch sử hoàn toàn sạch.

Không dùng reset để tiếp tục chấm cùng một incident mà không ghi rõ thời điểm, vì log có thể chứa nhiều lượt.
