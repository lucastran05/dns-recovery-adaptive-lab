# Báo cáo Northstar DNS Recovery

- Học viên / nhóm:
- Sandbox / training run:
- Thời gian và task variant:

## Hiện tượng ban đầu

Portal và File Server gặp vấn đề gì? Kèm kết quả authoritative, cache và HTTP identity.

## Timeline

| Timestamp | Nguồn bằng chứng | Record / key / source | Sự kiện | Nhận định |
|---|---|---|---|---|
| | | | | |

## Nguyên nhân

Quyền nào đã bị lạm dụng? Bằng chứng nào chỉ ra key và nguồn? Những điều gì chưa thể kết luận về danh tính người thực hiện?

## Biện pháp xử lý

Nêu thứ tự thu hồi quyền, khôi phục record, xử lý cache; lý do không tắt toàn bộ DNS.

## Kết quả xác minh

Đính kèm `dns-lab check`. Giải thích REFUSED, cập nhật recovery thành công, IP đúng và HTTP identity đúng. Nếu cache tự hết TTL, ghi rõ.

## Cải thiện

Đề xuất quản lý vòng đời TSIG keys, phân quyền record, giám sát update và quy trình thay đổi. Phân biệt DNSSEC với kiểm soát ai được sửa dữ liệu authoritative.
