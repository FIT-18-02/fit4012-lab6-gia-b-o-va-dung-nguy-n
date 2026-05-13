import os
import socket
from pathlib import Path
from aes_socket_utils import parse_key_packet, parse_length_header, recv_exact, decrypt_aes_cbc

# --- Cấu hình hệ thống từ môi trường hoặc mặc định ---
RECEIVER_HOST = os.getenv("RECEIVER_HOST", "127.0.0.1")
DATA_PORT = int(os.getenv("DATA_PORT", "6000"))
KEY_PORT = int(os.getenv("KEY_PORT", "6001"))
OUTPUT_FILE = os.getenv("OUTPUT_FILE", "sample_output.txt")
LOG_FILE = os.getenv("RECEIVER_LOG_FILE", "")

def run_receiver():
    print(f"--- [RECEIVER] Đang lắng nghe tại {RECEIVER_HOST} ---")

    # 1. Nhận Key và IV từ KEY_PORT (Kênh điều khiển)
    key_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Cho phép sử dụng lại địa chỉ cổng ngay lập tức sau khi đóng
    key_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    key_server.bind((RECEIVER_HOST, KEY_PORT))
    key_server.listen(1)
    print(f"[*] Đang chờ Key/IV tại cổng {KEY_PORT}...")
    
    conn_key, _ = key_server.accept()
    with conn_key:
        header = recv_exact(conn_key, 4)
        key_len = parse_length_header(header)
        # Nhận toàn bộ gói tin khóa: header + key + iv (16 bytes)
        packet = header + recv_exact(conn_key, key_len + 16)
        key, iv = parse_key_packet(packet)
    key_server.close()
    print(f"[OK] Đã nhận Key và IV thành công.")

    # 2. Nhận Bản mã từ DATA_PORT (Kênh dữ liệu)
    data_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    data_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    data_server.bind((RECEIVER_HOST, DATA_PORT))
    data_server.listen(1)
    print(f"[*] Đang chờ bản mã tại cổng {DATA_PORT}...")
    
    conn_data, _ = data_server.accept()
    with conn_data:
        header = recv_exact(conn_data, 4)
        ciphertext_len = parse_length_header(header)
        ciphertext = recv_exact(conn_data, ciphertext_len)
    data_server.close()
    print(f"[OK] Đã nhận bản mã ({ciphertext_len} bytes).")

    # 3. Giải mã và lưu kết quả
    try:
        # Giải mã trả về dữ liệu kiểu bytes
        plaintext_bytes = decrypt_aes_cbc(key, iv, ciphertext)
        
        # CHỖ SỬA QUAN TRỌNG: Chuyển bytes thành string UTF-8 để in và lưu file
        plaintext_str = plaintext_bytes.decode('utf-8')
        
        print(f"\n[>>>] Nội dung giải mã thành công: {plaintext_str}")
        
        # Lưu ra file sample_output.txt (hàm write_text cần string)
        Path(OUTPUT_FILE).write_text(plaintext_str, encoding="utf-8")
        
        # Ghi Log minh chứng cho CI
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
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            print(f"[*] Đã lưu minh chứng vào: {LOG_FILE}")
            
    except Exception as e:
        print(f"[!] Lỗi khi xử lý dữ liệu giải mã: {e}")

if __name__ == "__main__":
    run_receiver()