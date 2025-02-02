# Serum Injection Toolkit 

Serum is an **automated shellcode injector generator** that supports:

-  **Thread Creation** injection (WinAPI / NTDLL)
-  **Process Injection** (Inject shellcode into a running process)
-  **Process Hollowing** (Replace a process’s memory with another executable)

---

## Features
- Generates **C code** for different injection techniques.
- Supports **custom shellcode** via `msfvenom`.
- Compiles the payload into a Windows executable.
- **Cross-compilation support** (Linux → Windows).

---

## Installation
```bash
git clone https://github.com/Matthew20213/Serum-Injection-Toolkit.git
cd Serum-Injection-Toolkit
