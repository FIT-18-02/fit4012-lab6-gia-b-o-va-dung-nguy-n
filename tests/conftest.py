import sys
import os

# Thêm thư mục gốc vào PYTHONPATH để các bài test tìm thấy aes_socket_utils.py
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))