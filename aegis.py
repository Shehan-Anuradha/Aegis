#!/usr/bin/env python3
"""
AES-CTR + HMAC full-file encryption script
- Streams files in chunks to control memory usage
- Per-file AES-256 key + HMAC key encrypted under your Fernet master key
- Shows progress/ETA and current+peak memory
- Atomic file writes and mapfile that maps encrypted file names -> original paths
"""

import os
import sys
import uuid
import base64
import getpass
import struct
import tempfile
import time
import traceback
import psutil
from typing import Tuple, Iterator
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hmac, hashes
from cryptography.hazmat.backends import default_backend




def print_ascii_banner(indent: int = 10, delay: float = 0.1):
    banner = [
        "                               __           ",
        "                              |  \\          ",
        "  ______    ______    ______   \\$$  _______ ",
        " |      \\  /      \\  /      \\ |  \\ /       \\",
        "  \\$$$$$$\\|  $$$$$$\\|  $$$$$$\\| $$|  $$$$$$$",
        " /      $$| $$    $$| $$  | $$| $$ \\$$    \\ ",
        "|  $$$$$$$| $$$$$$$$| $$__| $$| $$ _\\$$$$$$\\",
        " \\$$    $$ \\$$     \\ \\$$    $$| $$|       $$",
        "  \\$$$$$$$  \\$$$$$$$ _\\$$$$$$$ \\$$ \\$$$$$$$ ",
        "                    |  \\__| $$              ",
        "                     \\$$    $$              ",
        "                      \\$$$$$$               "
    
    
    ]

    pad = " " * indent
    for line in banner:
        print(pad + line)
        sys.stdout.flush()
        time.sleep(delay)  # 0.05 faster, 0.2 slower

print_ascii_banner(indent=6, delay=0.08)


print("                                          Copyright of Shehan Anuradha, 2025")
print("                                                    A File encryption script")
print("\n ******************************************************************************")
print("\n")
























# --------------------------
# 🔑 Master key (Fernet)
# Replace these with your real values (or generate with a helper)
# --------------------------
SECRET_KEY = b'YOUR_SECRET_KEY_HERE'
ENCRYPTED_PASSWORD = b'YOUR_ENCRYPTED_PASSWORD_HERE'
cipher = Fernet(SECRET_KEY)

# --------------------------
# Paths & constants
# --------------------------
#SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
#MAP_FILE = os.path.join(SCRIPT_DIR, "file_map.txt")
#ERROR_LOG = os.path.join(SCRIPT_DIR, "encrypt_errors.log")
if getattr(sys, 'frozen', False):
    # Running from the .exe (PyInstaller bundle)
    SCRIPT_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    # Running as a normal .py script
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

MAP_FILE = os.path.join(SCRIPT_DIR, "file_map.txt")
ERROR_LOG = os.path.join(SCRIPT_DIR, "encrypt_errors.log")

CUSTOM_EXTENSION = ".aegis"          # encrypted file extension
AES_MAGIC = b"AESONLY1"              # file format magic
LEN_FMT = "!I"                       # 4-byte length prefix
HMAC_LEN = 32                        # bytes for HMAC-SHA256 tag
backend = default_backend()

# --------------------------
# Tunables (change safely)
# --------------------------
# CHUNK_SIZE sets how many bytes are read into memory at once.
# If you want to lock to 2 GB, set CHUNK_SIZE = 2048 * 1024 * 1024
# Make sure you have that RAM available.

CHUNK_SIZE = 2048 * 1024 * 1024

# If you prefer to lock to 2GB, uncomment:
# CHUNK_SIZE = 2048 * 1024 * 1024   # 2 GB

# --------------------------
# Progress & memory helpers
# --------------------------
def get_mem_mb() -> float:
    proc = psutil.Process(os.getpid())
    return proc.memory_info().rss / (1024 * 1024)

def human_bytes(n: int) -> str:
    # small helper
    for unit in ("B","KB","MB","GB","TB"):
        if n < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}PB"

def progress_bar(curr: int, total: int, start_time: float, peak_mem_mb: float, bar_len: int = 30) -> str:
    if total == 0:
        return "[No work]"
    ratio = curr / total
    filled = int(ratio * bar_len)
    bar = "#" * filled + "." * (bar_len - filled)
    percent = int(ratio * 100)
    elapsed = time.time() - start_time
    avg = elapsed / curr if curr > 0 else 0
    rem = total - curr
    eta = avg * rem if avg > 0 else 0
    if eta >= 3600:
        eta_s = f"{int(eta//3600)}h {int((eta%3600)//60)}m"
    elif eta >= 60:
        eta_s = f"{int(eta//60)}m {int(eta%60)}s"
    else:
        eta_s = f"{int(eta)}s"
    mem_now = f"{get_mem_mb():.1f}MB"
    mem_peak = f"{peak_mem_mb:.1f}MB"
    return f" [{bar}] {percent:3d}% ({curr}/{total}) ETA: {eta_s} | MEM: {mem_now} (peak {mem_peak})"

# --------------------------
# Utilities
# --------------------------
def encode_line(line: str) -> str:
    return base64.b64encode(line.encode("utf-8")).decode("utf-8")

def decode_line(line: str) -> str:
    return base64.b64decode(line.encode("utf-8")).decode("utf-8")

def check_password() -> bool:
    try:
        entered = getpass.getpass(" Enter password : ").encode()
    except (EOFError, KeyboardInterrupt):
        return False
    try:
        real_pass = cipher.decrypt(ENCRYPTED_PASSWORD)
    except InvalidToken:
        return False
    return entered == real_pass

def is_encrypted_file(path: str) -> bool:
    return path.endswith(CUSTOM_EXTENSION)

def walk_files(base_dir: str) -> Iterator[str]:
    for root, _, files in os.walk(base_dir):
        for name in files:
            yield os.path.join(root, name)

def log_error(path: str, exc: Exception) -> None:
    with open(ERROR_LOG, "a", encoding="utf-8") as f:
        f.write(f"==== {time.asctime()} ====\n{path}\n{''.join(traceback.format_exception(type(exc), exc, exc.__traceback__))}\n\n")

# --------------------------
# AES-CTR + HMAC format (AES-only)
# File format:
# [AES_MAGIC]
# [4-byte length enc_key_blob][enc_key_blob]
# [1-byte IV length][IV]
# [repeated: 4-byte chunk_len][ciphertext chunk]...
# [32-byte HMAC tag]  -- HMAC-SHA256 over (enc_key_blob || IV || all chunk_len+ciphertext)
# enc_key_blob = Fernet.encrypt(aes_key || b'||' || hmac_key)
# --------------------------
def encrypt_stream_aes_only(src_path: str, dst_path: str) -> None:
    # per-file keys
    aes_key = os.urandom(32)      # AES-256
    hmac_key = os.urandom(32)     # HMAC-SHA256 key
    key_blob = aes_key + b"||" + hmac_key
    enc_key_blob = cipher.encrypt(key_blob)  # protect keys with master Fernet

    iv = os.urandom(16)  # 128-bit IV for CTR
    hctx = hmac.HMAC(hmac_key, hashes.SHA256(), backend=backend)
    hctx.update(enc_key_blob)
    hctx.update(iv)

    fd, tmp_path = tempfile.mkstemp(prefix=".aes_enc_", dir=os.path.dirname(dst_path))
    os.close(fd)
    try:
        with open(src_path, "rb") as fin, open(tmp_path, "wb") as fout:
            # header
            fout.write(AES_MAGIC)
            fout.write(struct.pack(LEN_FMT, len(enc_key_blob)))
            fout.write(enc_key_blob)
            fout.write(struct.pack("B", len(iv)))
            fout.write(iv)
            # streaming encrypt with single CTR encryptor
            cipher_obj = Cipher(algorithms.AES(aes_key), modes.CTR(iv), backend=backend)
            encryptor = cipher_obj.encryptor()
            while True:
                chunk = fin.read(CHUNK_SIZE)
                if not chunk:
                    break
                ct = encryptor.update(chunk)
                fout.write(struct.pack(LEN_FMT, len(ct)))
                fout.write(ct)
                hctx.update(struct.pack(LEN_FMT, len(ct)))
                hctx.update(ct)
            final_ct = encryptor.finalize()
            if final_ct:
                fout.write(struct.pack(LEN_FMT, len(final_ct)))
                fout.write(final_ct)
                hctx.update(struct.pack(LEN_FMT, len(final_ct)))
                hctx.update(final_ct)
            tag = hctx.finalize()
            fout.write(tag)
            fout.flush()
            os.fsync(fout.fileno())
        os.replace(tmp_path, dst_path)
    except Exception:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise

def decrypt_stream_aes_only(src_path: str, dst_path: str) -> None:
    total_size = os.path.getsize(src_path)
    if total_size < len(AES_MAGIC):
        raise InvalidToken("File too small")
    fd, tmp_path = tempfile.mkstemp(prefix=".aes_dec_", dir=os.path.dirname(dst_path))
    os.close(fd)
    try:
        with open(src_path, "rb") as fin, open(tmp_path, "wb") as fout:
            magic = fin.read(len(AES_MAGIC))
            if magic != AES_MAGIC:
                raise InvalidToken("Not AES-only format")
            len_blob_b = fin.read(struct.calcsize(LEN_FMT))
            if len(len_blob_b) != struct.calcsize(LEN_FMT):
                raise InvalidToken("Truncated key blob length")
            (blob_len,) = struct.unpack(LEN_FMT, len_blob_b)
            enc_key_blob = fin.read(blob_len)
            if len(enc_key_blob) != blob_len:
                raise InvalidToken("Truncated key blob")
            iv_len_b = fin.read(1)
            if not iv_len_b:
                raise InvalidToken("Missing IV length")
            iv_len = struct.unpack("B", iv_len_b)[0]
            iv = fin.read(iv_len)
            if len(iv) != iv_len:
                raise InvalidToken("Truncated IV")
            # decrypt keys
            try:
                key_blob = cipher.decrypt(enc_key_blob)
            except InvalidToken:
                raise InvalidToken("Failed to decrypt per-file keys (bad master key or corrupted)")
            try:
                aes_key, hmac_key = key_blob.split(b"||", 1)
            except Exception:
                raise InvalidToken("Malformed key blob")
            # prepare HMAC verify
            hctx = hmac.HMAC(hmac_key, hashes.SHA256(), backend=backend)
            hctx.update(enc_key_blob)
            hctx.update(iv)
            # compute the position where HMAC tag begins
            end_of_cipher_pos = total_size - HMAC_LEN
            cipher_obj = Cipher(algorithms.AES(aes_key), modes.CTR(iv), backend=backend)
            decryptor = cipher_obj.decryptor()
            while fin.tell() < end_of_cipher_pos:
                len_b = fin.read(struct.calcsize(LEN_FMT))
                if not len_b:
                    break
                if len(len_b) < struct.calcsize(LEN_FMT):
                    raise InvalidToken("Truncated chunk length")
                (ct_len,) = struct.unpack(LEN_FMT, len_b)
                ct = fin.read(ct_len)
                if len(ct) != ct_len:
                    raise InvalidToken("Truncated ciphertext")
                hctx.update(len_b)
                hctx.update(ct)
                pt = decryptor.update(ct)
                fout.write(pt)
            final_p = decryptor.finalize()
            if final_p:
                fout.write(final_p)
            # read and verify tag
            fin.seek(end_of_cipher_pos)
            tag = fin.read(HMAC_LEN)
            if len(tag) != HMAC_LEN:
                raise InvalidToken("Missing HMAC tag")
            try:
                hctx.verify(tag)
            except Exception:
                raise InvalidToken("HMAC verification failed (corrupt/tampered)")
            fout.flush()
            os.fsync(fout.fileno())
        os.replace(tmp_path, dst_path)
    except Exception:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise

# Wrapper aliases (used by higher-level code)
def encrypt_stream_to_file(src: str, dst: str) -> None:
    # Always AES-only now
    # Writes atomically inside function already
    encrypt_stream_aes_only(src, dst)

def decrypt_stream_from_file(src: str, dst: str) -> None:
    # Detects AES-only format and decrypts
    decrypt_stream_aes_only(src, dst)

# --------------------------
# High-level operations & progress
# --------------------------
def scan_directory(base_dir: str) -> Tuple[int,int,int]:
    total = 0
    enc = 0
    for p in walk_files(base_dir):
        total += 1
        if is_encrypted_file(p):
            enc += 1
    return total, enc, total - enc

def encrypt_and_rename_files(base_dir: str) -> None:
    total, _, to_encrypt = scan_directory(base_dir)
    print(f" Found {to_encrypt} files to encrypt. Using CHUNK_SIZE={CHUNK_SIZE // (1024*1024)} MB")
    if to_encrypt == 0:
        return
    start = time.time()
    peak_mem = get_mem_mb()
    done = failed = 0
    with open(MAP_FILE, "w", encoding="utf-8") as mapf:
        for root, _, files in os.walk(base_dir):
            for filename in files:
                old_path = os.path.join(root, filename)
                if is_encrypted_file(old_path):
                    continue
                new_path = os.path.join(root, f"{uuid.uuid4()}{CUSTOM_EXTENSION}")
                try:
                    encrypt_stream_to_file(old_path, new_path)
                    mapf.write(encode_line(f"{new_path}|{old_path}") + "\n")
                    mapf.flush()
                    os.fsync(mapf.fileno())
                    os.remove(old_path)
                    done += 1
                except Exception as e:
                    failed += 1
                    log_error(old_path, e)
                # update peak mem
                mnow = get_mem_mb()
                if mnow > peak_mem:
                    peak_mem = mnow
                # progress
                bar = progress_bar(done + failed, to_encrypt, start, peak_mem)
                print("\r" + bar, end="", flush=True)
    print()
    print(f" Encrypted {done}, Failed {failed}. Peak RAM: {peak_mem:.1f} MB")

def restore_files_with_map() -> None:
    if not os.path.exists(MAP_FILE):
        print(" No mapping file found.")
        return
    if not check_password():
        print("❌ Wrong password.")
        return
    with open(MAP_FILE, "r", encoding="utf-8") as f:
        lines = [ln.strip() for ln in f if ln.strip()]
    total = len(lines)
    print(f" Files to restore: {total}")
    if total == 0:
        return
    start = time.time()
    done = failed = 0
    peak_mem = get_mem_mb()
    for line in lines:
        try:
            new_path, old_path = decode_line(line).split("|", 1)
            if not os.path.exists(new_path):
                failed += 1
                log_error(new_path, Exception("Missing encrypted file"))
            else:
                os.makedirs(os.path.dirname(old_path) or ".", exist_ok=True)
                decrypt_stream_from_file(new_path, old_path)
                os.remove(new_path)
                done += 1
        except Exception as e:
            failed += 1
            log_error(line, e)
        mnow = get_mem_mb()
        if mnow > peak_mem:
            peak_mem = mnow
        bar = progress_bar(done + failed, total, start, peak_mem)
        print("\r" + bar, end="", flush=True)
    print()
    try:
        os.remove(MAP_FILE)
    except Exception:
        pass
    print(f" Restored {done}, Failed {failed}. Peak RAM: {peak_mem:.1f} MB")

def restore_files_without_map(base_dir: str) -> None:
    enc_paths = [p for p in walk_files(base_dir) if is_encrypted_file(p)]
    total = len(enc_paths)
    print(f" Found {total} encrypted files to restore (mapless).")
    if total == 0:
        return
    if not check_password():
        print("❌ Wrong password.")
        return
    start = time.time()
    done = failed = 0
    peak_mem = get_mem_mb()
    for src in enc_paths:
        base_no_ext = os.path.splitext(os.path.basename(src))[0]
        dst = os.path.join(os.path.dirname(src), base_no_ext)
        if os.path.exists(dst):
            dst = os.path.join(os.path.dirname(src), base_no_ext + "_restored")
        try:
            decrypt_stream_from_file(src, dst)
            os.remove(src)
            done += 1
        except Exception as e:
            failed += 1
            log_error(src, e)
        mnow = get_mem_mb()
        if mnow > peak_mem:
            peak_mem = mnow
        bar = progress_bar(done + failed, total, start, peak_mem)
        print("\r" + bar, end="", flush=True)
    print()
    print(f" Mapless restore complete. Restored={done}, Failed={failed}. Peak RAM: {peak_mem:.1f} MB")
    print(f" Warning !!! files are restored without thier extentions !!!  ")

# --------------------------
# Main CLI flow
# --------------------------
def main():
    print(f" aegis AES-only (chunk={CHUNK_SIZE // (1024*1024)} MB).")
    if os.path.exists(MAP_FILE):
        if not check_password():
            print("❌ Wrong password.")
            return
        restore_files_with_map()
    else:
        print(" 1) Encrypt a folder")
        print(" 2) Restore encrypted files (no map)")
        choice = input(" Select [1/2]: ").strip()
        if choice == "1":
            base_dir = input(" Folder to encrypt: ").strip()
            if not os.path.isdir(base_dir):
                print("❌ Invalid folder.")
                return
            encrypt_and_rename_files(base_dir)
        elif choice == "2":
            base_dir = input(" Folder containing .enc files: ").strip()
            if not os.path.isdir(base_dir):
                print("❌ Invalid folder.")
                return
            if not check_password():
                print("❌ Wrong password.")
                return
            restore_files_without_map(base_dir)
        else:
            print("❌ Invalid choice.")

if __name__ == "__main__":
    main()
