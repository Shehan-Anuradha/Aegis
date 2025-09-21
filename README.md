<p align="center">
  <img src="assets/Aegisbanner.png" alt="Aegis Banner" width="100%"/>
</p>

# 🛡️ Aegis  
**AES-CTR + HMAC based file encryption tool with progress bar and memory-efficient streaming.**

![Aegis Banner](./assets/banner.png)

---

## 🔒 About  
Aegis is a Python-based file encryption and decryption tool built for **security + usability**.  
It uses **AES-256 in CTR mode** for fast and strong encryption, combined with **HMAC-SHA256** for integrity checks.  

Unlike heavy disk encryption tools, Aegis is:  
- **Lightweight** – works on folders/files directly  
- **Memory-friendly** – streams large files in chunks (you control RAM usage)  
- **Secure** – random keys per file, wrapped with your master key  
- **User-friendly** – progress bar, ETA, and memory usage display  

---

## ✨ Features  
✔ AES-CTR 256-bit encryption + HMAC-SHA256 integrity  
✔ Per-file random keys, wrapped with master key  
✔ Streaming in chunks (set your own memory cap, e.g., 2GB)  
✔ Progress bar with ETA for large batches  
✔ Memory usage stats during encryption/decryption  
✔ Automatic restore with or without file mapping  
✔ ASCII-art banner for that “movie hacker” vibe 😎  

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

