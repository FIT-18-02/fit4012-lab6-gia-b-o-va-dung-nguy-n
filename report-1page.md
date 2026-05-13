# Report 1 page - Lab 6 AES-CBC Socket

## Thông tin nhóm

- Thành viên 1: Nguyễn Anh Dũng - MSSV: 1871020167
- Thành viên 2: Ngô Gia Bảo - MSSV: 1871020072

## Mục tiêu

Mục tiêu của bài thực hành là xây dựng hệ thống truyền nhận dữ liệu an toàn qua TCP Socket sử dụng thuật toán AES-128 chế độ CBC. Hệ thống thực hiện phân tách luồng điều khiển (KEY_PORT) để trao đổi khóa/IV và luồng dữ liệu (DATA_PORT) để gửi bản mã. Qua đó, nhóm nắm vững cách triển khai PKCS#7 padding, xử lý Header độ dài trong lập trình mạng và đánh giá các điểm yếu bảo mật khi trao đổi khóa trực tiếp.

## Phân công thực hiện

- **Nguyễn Anh Dũng**: Phụ trách chính phần Sender, thiết kế logic kênh truyền khóa (KEY_PORT), và cài đặt các hàm mã hóa AES-CBC trong thư viện dùng chung.
- **Ngô Gia Bảo**: Phụ trách chính phần Receiver, thiết kế logic kênh dữ liệu (DATA_PORT), thực hiện giải mã và xử lý gỡ bỏ padding.
- **Phần làm chung**: Xây dựng bộ mã nguồn `aes_socket_utils.py`, viết kịch bản kiểm thử (tests), thu thập log minh chứng và phân tích mô hình đe dọa (threat model).

## Cách làm

- **AES-CBC & Padding**: Sử dụng thư viện `pycryptodome` để triển khai AES chế độ CBC với PKCS#7 padding giúp đảm bảo dữ liệu luôn khớp với kích thước khối 16-byte.
- **Kênh truyền (Channels)**: Tách biệt KEY_PORT (6001) để gửi Key/IV và DATA_PORT (6000) để truyền ciphertext nhằm mô phỏng kiến trúc kênh điều khiển riêng biệt.
- **Giao thức Socket**: Thiết kế Header 4-byte (unsigned int) đi kèm trước mỗi gói tin để thông báo chính xác độ dài dữ liệu, giúp Receiver tránh lỗi nhận thiếu hoặc tràn bộ đệm qua TCP.

## Kết quả

- **Chạy demo**: Hệ thống truyền nhận thành công tin nhắn từ file `sample_input.txt` và hiển thị chính xác kết quả tại `sample_output.txt`.
- **Log minh chứng**: Các file trong thư mục `logs/` ghi nhận đầy đủ quá trình bắt tay, trao đổi khóa thành công và giải mã bản rõ hoàn chỉnh.
- **Kiểm thử**: Vượt qua ít nhất 6 bài kiểm tra tự động, bao gồm các kịch bản đúng khóa, sai khóa và dữ liệu bị giả mạo trên đường truyền.

## Kết luận

- **Bài học kỹ thuật**: Việc xử lý Header độ dài là bắt buộc để đảm bảo tính toàn vẹn của dữ liệu khi truyền qua Socket TCP.
- **Bài học bảo mật**: Mã hóa dữ liệu bằng AES-CBC là chưa đủ an toàn nếu kênh truyền khóa (Key/IV) không được bảo vệ bằng các phương thức như RSA hoặc trao đổi khóa Diffie-Hellman.