import os
import socket
from pathlib import Path

from aes_socket_utils import (
    build_data_packet,
    build_key_packet,
    encrypt_aes_cbc
)

# --- Cấu hình hệ thống từ môi trường hoặc mặc định ---
SERVER_IP = os.getenv("SERVER_IP", "127.0.0.1")
DATA_PORT = int(os.getenv("DATA_PORT", "6000"))
KEY_PORT = int(os.getenv("KEY_PORT", "6001"))
AES_KEY_SIZE = int(os.getenv("AES_KEY_SIZE", "16"))
MESSAGE_ENV = os.getenv("MESSAGE")
INPUT_FILE = os.getenv("INPUT_FILE", "")
LOG_FILE = os.getenv("SENDER_LOG_FILE", "")
TIMEOUT = float(os.getenv("SOCKET_TIMEOUT", "10"))


def get_plaintext() -> bytes:
    """Đọc bản rõ từ file, biến môi trường hoặc nhập từ bàn phím."""

    if INPUT_FILE and Path(INPUT_FILE).exists():
        return Path(INPUT_FILE).read_bytes()

    if MESSAGE_ENV is not None:
        return MESSAGE_ENV.encode("utf-8")

    return input("Nhập nội dung cần gửi: ").encode("utf-8")


def send_packet(host: str, port: int, packet: bytes) -> None:
    """Thực hiện kết nối TCP và gửi gói tin."""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(TIMEOUT)
        sock.connect((host, port))
        sock.sendall(packet)


def main() -> None:
    print("--- [SENDER] Khởi tạo quy trình gửi dữ liệu AES-CBC ---")

    # ==================================================
    # 1. Chuẩn bị dữ liệu và mã hóa
    # ==================================================
    try:
        plaintext = get_plaintext()

        key, iv, ciphertext = encrypt_aes_cbc(
            plaintext,
            key_size=AES_KEY_SIZE
        )

    except Exception as e:
        print(f"[!] Lỗi khi chuẩn bị dữ liệu: {e}")
        return

    # ==================================================
    # 2. Đóng gói dữ liệu
    # ==================================================
    key_packet = build_key_packet(key, iv)

    data_packet = build_data_packet(ciphertext)

    # ==================================================
    # 3. Gửi qua hai kênh độc lập
    # ==================================================
    try:
        # Gửi Key/IV trước
        send_packet(
            SERVER_IP,
            KEY_PORT,
            key_packet
        )

        print("[+] Đã gửi key/IV qua kênh khóa.")

        # Gửi Ciphertext sau
        send_packet(
            SERVER_IP,
            DATA_PORT,
            data_packet
        )

        print("[+] Đã gửi ciphertext qua kênh dữ liệu.")

    except Exception as e:
        print(f"[!] Lỗi kết nối Socket: {e}")
        print("Gợi ý: Hãy đảm bảo Receiver đã được bật trước khi chạy Sender.")
        return

    # ==================================================
    # 4. Hiển thị thông tin
    # ==================================================
    lines = [
        "==========================================",
        "[+] TRẠNG THÁI: Gửi dữ liệu thành công!",
        f"[+] Server: {SERVER_IP}",
        f"[+] Key Channel (Port): {KEY_PORT}",
        f"[+] Data Channel (Port): {DATA_PORT}",
        f"[+] AES Key Size: {len(key) * 8} bits",
        f"[+] Key (hex): {key.hex()}",
        f"[+] IV (hex):  {iv.hex()}",
        f"[+] Plaintext: {len(plaintext)} bytes",
        f"[+] Ciphertext: {len(ciphertext)} bytes",
        "==========================================",
    ]

    for line in lines:
        print(line)

    # ==================================================
    # 5. Ghi log cho CI
    # ==================================================
    if LOG_FILE:
        log_path = Path(LOG_FILE)

        log_path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        log_path.write_text(
            "\n".join(lines) + "\n",
            encoding="utf-8"
        )

        print(f"[*] Đã lưu minh chứng vào: {LOG_FILE}")


if __name__ == "__main__":
    main()