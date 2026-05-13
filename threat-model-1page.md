# Threat Model - Lab 6 AES-CBC Socket

## Thông tin nhóm

- Thành viên 1: Nguyễn Anh Dũng - MSSV: 1871020167
- Thành viên 2: Ngô Gia Bảo - MSSV: 1871020072

## Assets

Các tài sản quan trọng cần bảo vệ bao gồm:
- **Bản rõ (Plaintext)**: Nội dung thông tin gốc chứa trong file `sample_input.txt` hoặc biến môi trường.
- **Khóa AES (Key) & IV**: Thành phần then chốt để thực hiện mã hóa và giải mã AES-128.
- **Bản mã (Ciphertext)**: Dữ liệu đã được mã hóa truyền qua DATA_PORT.
- **Dữ liệu Log**: Các file ghi chép tiến trình hoạt động của hệ thống trong thư mục `logs/`.

## Attacker model

Đối tượng tấn công giả định trong bài Lab này là:
- Kẻ tấn công có khả năng nghe lén (Eavesdropping) trên mạng nội bộ (LAN) để bắt các gói tin TCP.
- Có khả năng can thiệp, sửa đổi (Tampering) gói tin bản mã trên đường truyền.
- Có thể thực hiện gửi lại các gói tin cũ (Replay attack) hoặc truy cập trái phép vào các file log nếu hệ thống không được phân quyền tốt.

## Threats

Hệ thống hiện tại đối mặt với các mối đe dọa cụ thể sau:
- **Lộ khóa (Key disclosure)**: Do cơ chế KEY_PORT hiện tại gửi Key và IV dưới dạng văn bản rõ (plaintext), kẻ tấn công bắt được gói tin này sẽ vô hiệu hóa hoàn toàn lớp bảo mật AES.
- **Giả mạo dữ liệu (Tampering)**: Chế độ AES-CBC chỉ đảm bảo tính bí mật, không đảm bảo tính toàn vẹn. Kẻ tấn công có thể thay đổi bit trong ciphertext, khiến Receiver giải mã ra dữ liệu sai lệch.
- **Thiếu xác thực (No authentication)**: Receiver không có cơ chế kiểm tra định danh của Sender, dẫn đến rủi ro bất kỳ ai cũng có thể gửi dữ liệu giả mạo tới Receiver.
- **Lộ thông tin qua Log (Log leakage)**: Nếu các hàm hiển thị ghi trực tiếp giá trị Key/IV vào log file mà không được bảo vệ, kẻ tấn công có thể lấy được khóa từ lịch sử hệ thống.

## Mitigations

Các biện pháp nhằm giảm thiểu rủi ro cho hệ thống:
- **Mã hóa kênh truyền**: Trong thực tế, cần sử dụng giao thức TLS/SSL để mã hóa toàn bộ luồng dữ liệu socket.
- **Trao đổi khóa an toàn**: Thay vì gửi Key/IV trực tiếp, cần sử dụng RSA (mã hóa bất đối xứng) hoặc Diffie-Hellman để trao đổi khóa an toàn.
- **Xác thực và Toàn vẹn**: Chuyển sang sử dụng AES-GCM (Authenticated Encryption) để vừa mã hóa vừa đảm bảo dữ liệu không bị sửa đổi.
- **Quản lý Log**: Không ghi các giá trị nhạy cảm như Key thực vào log trong môi trường sản xuất; chỉ ghi mã băm (hash) hoặc trạng thái thành công/thất bại.

## Residual risks

Rủi ro còn lại lớn nhất là hệ thống vẫn chưa an toàn tuyệt đối vì Kênh Khóa (Key channel) trong bài Lab này chỉ mang tính chất mô phỏng học tập. Hệ thống hiện vẫn thiếu cơ chế xác thực Sender/Receiver và chưa có lớp bảo vệ chống tấn công phát lại (Replay attack) một cách đầy đủ.