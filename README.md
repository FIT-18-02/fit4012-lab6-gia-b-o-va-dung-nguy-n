[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/pP7_NUvP)
# FIT4012 - Lab 6 - Hệ thống gửi và nhận dữ liệu mã hóa AES-CBC qua Socket

Repo starter kit này dùng cho **Lab 6**: gửi và nhận dữ liệu mã hóa bằng **AES-CBC** qua **TCP socket**.

Lab này kế thừa ý tưởng từ Lab 3 DES Socket, nhưng nâng cấp theo 2 hướng:

1. Chuyển từ **DES-CBC** sang **AES-CBC**.
2. Tách thành **2 kênh TCP**:
   - `KEY_PORT`: kênh giả lập trao đổi AES key và IV.
   - `DATA_PORT`: kênh gửi ciphertext.

> Lưu ý quan trọng: kênh khóa trong bài này chỉ là mô phỏng học tập. Key và IV vẫn được gửi plaintext, vì vậy thiết kế này **không an toàn để dùng trong hệ thống thật**.

---

## Team members

- **Thành viên 1**: Nguyễn Anh Dũng - MSSV: 1871020167
- **Thành viên 2**: Ngô Gia Bảo - MSSV: 1871020072

## Task division

- **Thành viên 1 phụ trách chính**: Cài đặt logic `sender.py`, quản lý KEY_PORT và xây dựng hàm mã hóa trong `aes_socket_utils.py`.
- **Thành viên 2 phụ trách chính**: Cài đặt logic `receiver.py`, quản lý DATA_PORT và thực hiện giải mã dữ liệu.
- **Phần làm chung**: Thiết kế kịch bản kiểm thử (tests), viết báo cáo và phân tích mô hình đe dọa.

## Demo roles

- **Demo Sender / kênh khóa / log gửi**: Nguyễn Anh Dũng
- **Demo Receiver / kênh dữ liệu / giải mã**: Ngô Gia Bảo
- **Cả hai cùng trả lời threat model và ethics**: Cả nhóm cùng thực hiện

---

## Mục tiêu học tập

Sau bài lab này, sinh viên có thể:

- Mô tả được luồng Sender/Receiver qua TCP socket.
- Phân biệt được kênh khóa và kênh dữ liệu.
- Cài đặt được AES-CBC với key, IV và PKCS#7 padding.
- Thiết kế được header độ dài cho dữ liệu truyền qua socket.
- Viết test cho các tình huống đúng và sai.
- Nhận diện được điểm yếu của việc gửi key/IV plaintext.

---

## Cấu trúc repo

```text
.
├── aes_socket_utils.py
├── sender.py
├── receiver.py
├── requirements.txt
├── sample_input.txt
├── sample_output.txt
├── report-1page.md
├── threat-model-1page.md
├── peer-review-response.md
├── logs/
├── tests/
└── .github/workflows/ci.yml