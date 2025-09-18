# 🛡️ Aegis – File Encryption Tool

Aegis is a Python-based file encryption tool that uses **AES-CTR (AES-256)** for encryption and **HMAC-SHA256** for integrity verification.
It’s designed for personal use, with features like streaming large files in chunks, memory usage tracking, and atomic file operations.

---

## ✨ Features

* 🔑 **AES-256 CTR mode** for strong file encryption
* 🛡️ **HMAC-SHA256** for integrity verification
* 📂 **Streaming encryption** – handles very large files without loading them fully into memory
* 📊 **Progress bar with ETA & memory tracking**
* 🗂️ **Map file** to restore original file names after encryption
* 🧹 **Atomic writes** – ensures safe encryption even if the process is interrupted

---

## 🚀 Getting Started

### Prerequisites

* Python 3.8+
* Install dependencies:

```bash
pip install cryptography psutil
```

---

### Usage

Run the script:

```bash
python3 aegis.py
```

Menu options:

1. **Encrypt a folder** → Encrypts all files in a given directory (skips already encrypted files).
2. **Restore encrypted files (mapless)** → Attempts to decrypt without using the mapping file (file extensions may be lost).

---

### Example Workflow

**Encrypt a folder:**

```bash
$ python3 aegis.py
 1) Encrypt a folder
 2) Restore encrypted files (no map)
 Select [1/2]: 1
 Folder to encrypt: /path/to/files
 Found 10 files to encrypt...
 [###########...............] 45% (5/10) ETA: 12s | MEM: 150.2MB (peak 160.5MB)
```

**Restore files:**

```bash
$ python3 aegis.py
 1) Encrypt a folder
 2) Restore encrypted files (no map)
 Select [1/2]: 2
 Folder containing .aegis files: /path/to/encrypted
 Files to restore: 10
 [#######################...] 90% (9/10) ETA: 3s | MEM: 142.3MB (peak 150.0MB)
```

---

## ⚠️ Notes & Limitations

* This is a **personal/learning project** and not meant as a replacement for production-grade encryption tools.
* Do not hardcode secrets in the script. Use environment variables or secure key storage.
* If restoring without a map file, original file extensions may be lost.

---

## 📖 What I Learned

Building this project helped me explore:

* How to implement **AES-CTR + HMAC** securely
* Handling **large files efficiently** with streaming
* Adding usability features like progress bars and memory tracking
* Secure file operations using atomic writes

---

## 📜 License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.

---

