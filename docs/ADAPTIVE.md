# Thiết kế adaptive

Thời lượng 100 phút: 85 phút cho 5 Training Phases, khoảng 15 phút cho giới thiệu, questionnaire, access và phản hồi.

Cấu trúc `training.json` dựa trên mẫu Adaptive chính thức đã đối chiếu:

- https://docs.platform.cyberrange.cz/user-guide-basic/training-agenda/training-definition/adaptive-training-definition/
- https://github.com/cyberrangecz/library-demo-training-adaptive/blob/master/training.json

Sử dụng `phases`, `phase_type`, `tasks`, `decision_matrix`, `questionnaire_type`, `phase_relations`. Không dùng `levels` của linear training.

| Variant | Thiết kế |
|---|---|
| order 0, nâng cao | Tự chọn bằng chứng, phân biệt nguyên nhân và giải thích giới hạn |
| order 1, tiêu chuẩn | Nêu công cụ/nguồn dữ liệu, yêu cầu tự xác định trường cần đọc |
| order 2, cơ bản | Hướng dẫn lệnh và trường kết quả cụ thể |

Mỗi Training Phase có một câu questionnaire liên quan. Matrix hiện tại đặt questionnaire_answered=1 cho phase hiện tại; completed_in_time=1, solution_displayed=1 và wrong_answers=1 cho phase trước. Các trọng số khác bằng 0. Keyword metric bằng 0 vì chưa xác minh tích hợp command logging của platform.

Matrix có lần lượt 1, 2, 3, 4, 5 rows theo pattern mẫu. Đây là trọng số khởi đầu, cần dùng simulator của bản platform đang triển khai để kiểm tra. Không tự suy diễn ngưỡng hay công thức riêng của engine.

Task variants dùng cùng đáp án cốt lõi trong mỗi phase, khác mức hỗ trợ và yêu cầu lập luận. Phần lập luận/báo cáo chấm riêng. `modify_sandbox=false`: cơ chế adaptive chọn task; hạ tầng và sự cố không thay đổi theo variant.

Trước Release, thử ít nhất: học viên mạnh, học viên yếu, học viên tiến bộ qua các phase và học viên giỏi DNS nhưng yếu xử lý sự cố. Kiểm tra task order trong editor và kết quả simulator.

Gói chưa được import vào instance của người dùng. Nếu validator bản cài khác schema mẫu, export một Adaptive Definition từ chính bản đó rồi đối chiếu; không đổi tùy ý enum hoặc tên trường.
