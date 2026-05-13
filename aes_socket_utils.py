"""
Thư viện dùng chung cho Lab 6: AES-CBC Socket
Nhóm thực hiện: Nguyễn Anh Dũng & Ngô Gia Bảo
"""

import os
import struct
from typing import Tuple
from Crypto.Cipher import AES

# Các hằng số cấu hình hệ thống
BLOCK_SIZE = 16
LENGTH_HEADER_SIZE = 4
KEY_LENGTH_HEADER_SIZE = 4
IV_SIZE = 16
VALID_KEY_SIZES = (16, 32)


def pad(data: bytes) -> bytes:
    """Thêm PKCS#7 padding để dữ liệu khớp với kích thước khối AES (16 bytes)."""

    if not isinstance(data, bytes):
        raise TypeError("Dữ liệu đầu vào phải là bytes.")

    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len


def unpad(data: bytes) -> bytes:
    """Kiểm tra và gỡ bỏ PKCS#7 padding sau khi giải mã."""

    if not isinstance(data, bytes):
        raise TypeError("Dữ liệu đầu vào phải là bytes.")

    if not data:
        raise ValueError("Dữ liệu rỗng, không thể gỡ padding.")

    pad_len = data[-1]

    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Giá trị padding không hợp lệ.")

    expected = bytes([pad_len]) * pad_len

    if data[-pad_len:] != expected:
        raise ValueError("Cấu trúc PKCS#7 padding bị sai hoặc dữ liệu bị hỏng.")

    return data[:-pad_len]


def generate_key_iv(key_size: int = 16) -> Tuple[bytes, bytes]:
    """Khởi tạo ngẫu nhiên Key và IV."""

    if key_size not in VALID_KEY_SIZES:
        raise ValueError("AES key size phải là 16 hoặc 32 bytes.")

    return os.urandom(key_size), os.urandom(IV_SIZE)


def validate_key_iv(key: bytes, iv: bytes) -> None:
    """Xác thực độ dài của Key và IV."""

    if not isinstance(key, bytes):
        raise TypeError("Key phải là bytes.")

    if not isinstance(iv, bytes):
        raise TypeError("IV phải là bytes.")

    if len(key) not in VALID_KEY_SIZES:
        raise ValueError("AES key phải dài đúng 16 hoặc 32 byte.")

    if len(iv) != IV_SIZE:
        raise ValueError("IV cho chế độ AES-CBC phải dài đúng 16 byte.")


def encrypt_aes_cbc(
    plain: bytes,
    key: bytes = None,
    iv: bytes = None,
    key_size: int = 16
) -> Tuple[bytes, bytes, bytes]:
    """Thực hiện mã hóa AES-CBC."""

    if not isinstance(plain, bytes):
        raise TypeError("Plaintext phải là bytes.")

    if key is None or iv is None:
        key, iv = generate_key_iv(key_size)

    validate_key_iv(key, iv)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_bytes = cipher.encrypt(pad(plain))

    return key, iv, cipher_bytes


def decrypt_aes_cbc(key: bytes, iv: bytes, cipher_bytes: bytes) -> bytes:
    """Thực hiện giải mã AES-CBC."""

    if not isinstance(cipher_bytes, bytes):
        raise TypeError("Ciphertext phải là bytes.")

    validate_key_iv(key, iv)

    if not cipher_bytes:
        raise ValueError("Bản mã không được rỗng.")

    if len(cipher_bytes) % BLOCK_SIZE != 0:
        raise ValueError("Độ dài ciphertext không hợp lệ.")

    cipher = AES.new(key, AES.MODE_CBC, iv)

    return unpad(cipher.decrypt(cipher_bytes))


def build_key_packet(key: bytes, iv: bytes) -> bytes:
    """Đóng gói Key/IV: [Độ dài Key(4b)] + [Key] + [IV(16b)]."""

    validate_key_iv(key, iv)

    return struct.pack("!I", len(key)) + key + iv


def parse_key_packet(packet: bytes) -> Tuple[bytes, bytes]:
    """Phân tích gói tin khóa."""

    if not isinstance(packet, bytes):
        raise TypeError("packet phải là bytes.")

    if len(packet) < KEY_LENGTH_HEADER_SIZE + IV_SIZE:
        raise ValueError("Gói tin khóa không hợp lệ.")

    key_len = struct.unpack(
        "!I",
        packet[:KEY_LENGTH_HEADER_SIZE]
    )[0]

    if key_len not in VALID_KEY_SIZES:
        raise ValueError("Độ dài key không hợp lệ.")

    expected_size = KEY_LENGTH_HEADER_SIZE + key_len + IV_SIZE

    if len(packet) != expected_size:
        raise ValueError("Kích thước packet không đúng.")

    key = packet[
        KEY_LENGTH_HEADER_SIZE:
        KEY_LENGTH_HEADER_SIZE + key_len
    ]

    iv = packet[
        KEY_LENGTH_HEADER_SIZE + key_len:
    ]

    validate_key_iv(key, iv)

    return key, iv


def build_data_packet(cipher_bytes: bytes) -> bytes:
    """Đóng gói bản mã: [Độ dài(4b)] + [Bản mã]."""

    if not isinstance(cipher_bytes, bytes):
        raise TypeError("cipher_bytes phải là bytes.")

    return struct.pack("!I", len(cipher_bytes)) + cipher_bytes


def parse_length_header(header: bytes) -> int:
    """Phân tích 4 byte header để lấy độ dài."""

    if not isinstance(header, bytes):
        raise TypeError("header phải là bytes.")

    if len(header) != LENGTH_HEADER_SIZE:
        raise ValueError("Header phải dài đúng 4 byte.")

    return struct.unpack("!I", header)[0]


def recv_exact(conn, n: int) -> bytes:
    """Nhận chính xác n byte từ Socket."""

    if n < 0:
        raise ValueError("Số byte cần nhận không hợp lệ.")

    chunks = []
    received = 0

    while received < n:
        chunk = conn.recv(n - received)

        if not chunk:
            raise ConnectionError("Kết nối bị đóng bất ngờ.")

        chunks.append(chunk)
        received += len(chunk)

    return b"".join(chunks)