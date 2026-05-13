import os
import socket
from pathlib import Path

from aes_socket_utils import (
    parse_key_packet,
    parse_length_header,
    recv_exact,
    decrypt_aes_cbc
)

# --- Cấu hình hệ thống từ môi trường hoặc mặc định ---
RECEIVER_HOST = os.getenv("RECEIVER_HOST", "127.0.0.1")
DATA_PORT = int(os.getenv("DATA_PORT", "6000"))
KEY_PORT = int(os.getenv("KEY_PORT", "6001"))
OUTPUT_FILE = os.getenv("OUTPUT_FILE", "sample_output.txt")
LOG_FILE = os.getenv("RECEIVER_LOG_FILE", "")
TIMEOUT = float(os.getenv("SOCKET_TIMEOUT", "10"))


def run_receiver():
    print(f"--- [RECEIVER] Đang lắng nghe tại {RECEIVER_HOST} ---")

    key_server = None
    data_server = None

    try:
        # ==================================================
        # 1. Nhận KEY + IV
        # ==================================================
        key_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        key_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # THÊM TIMEOUT
        key_server.settimeout(TIMEOUT)

        key_server.bind((RECEIVER_HOST, KEY_PORT))
        key_server.listen(1)

        print(f"[*] Đang lắng nghe kênh khóa tại cổng {KEY_PORT}...")

        conn_key, _ = key_server.accept()

        with conn_key:
            conn_key.settimeout(TIMEOUT)

            header = recv_exact(conn_key, 4)

            key_len = parse_length_header(header)

            packet = header + recv_exact(
                conn_key,
                key_len + 16
            )

            key, iv = parse_key_packet(packet)

        key_server.close()

        print("[OK] Đã nhận Key và IV thành công.")

        # ==================================================
        # 2. Nhận ciphertext
        # ==================================================
        data_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        data_server.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1
        )

        # THÊM TIMEOUT
        data_server.settimeout(TIMEOUT)

        data_server.bind((RECEIVER_HOST, DATA_PORT))
        data_server.listen(1)

        print(f"[*] Đang lắng nghe kênh dữ liệu tại cổng {DATA_PORT}...")

        conn_data, _ = data_server.accept()

        with conn_data:
            conn_data.settimeout(TIMEOUT)

            header = recv_exact(conn_data, 4)

            ciphertext_len = parse_length_header(header)

            ciphertext = recv_exact(
                conn_data,
                ciphertext_len
            )

        data_server.close()

        print(f"[OK] Đã nhận bản mã ({ciphertext_len} bytes).")

        # ==================================================
        # 3. Giải mã
        # ==================================================
        plaintext_bytes = decrypt_aes_cbc(
            key,
            iv,
            ciphertext
        )

        plaintext_str = plaintext_bytes.decode("utf-8")

        print(f"\n[>>>] Nội dung giải mã thành công: {plaintext_str}")

        Path(OUTPUT_FILE).write_text(
            plaintext_str,
            encoding="utf-8"
        )

        if LOG_FILE:
            lines = [
                "==========================================",
                "[+] TRẠNG THÁI: Nhận và giải mã thành công!",
                f"[+] Key (hex): {key.hex()}",
                f"[+] IV (hex):  {iv.hex()}",
                f"[+] Ciphertext: {ciphertext_len} bytes",
                f"[+] Decrypted: {plaintext_str}",
                "==========================================",
            ]

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

    except socket.timeout:
        print("[!] Socket timeout.")

    except Exception as e:
        print(f"[!] Lỗi: {e}")

    finally:
        if key_server:
            key_server.close()

        if data_server:
            data_server.close()


if __name__ == "__main__":
    run_receiver()