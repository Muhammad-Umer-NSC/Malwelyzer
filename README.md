# Malwelyzer

# 🔍 Static Malware Analysis Toolkit

> A powerful, beginner-friendly static malware analysis script for Windows. Drop in your tools, add your API key, and run. That's it.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=flat-square&logo=windows)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Libraries](https://img.shields.io/badge/Libraries-Auto--Installed-brightgreen?style=flat-square)

---

## 📸 What It Does

Run one command and get a full static analysis of any file — executable, DLL, or binary — including:

- **File metadata** — size, timestamps, magic bytes
- **Cryptographic hashes** — MD5, SHA1, SHA256, SHA512
- **Entropy analysis** — detects packed or encrypted files
- **File type detection** — via TrID and Detect-It-Easy
- **String extraction** — via Sysinternals strings.exe and FLOSS (including obfuscated strings)
- **Suspicious string detection** — flags dangerous APIs, PowerShell, registry keys, encoded commands, and more
- **PE file analysis** — sections, imports, exports, compile time, TLS callbacks, overlay data
- **YARA scanning** — built-in rules covering Ransomware, RAT, Banker, Dropper, Rootkit, Worm, Spyware, and Packers
- **VirusTotal integration** — automatic hash lookup with fallback to file upload
- **Network indicators** — extracts hardcoded IPs, URLs, domains, and email addresses
- **Malware classification** — scores and identifies the most likely malware type with evidence
- **HTML report** — saves a beautiful dark-themed report you can open in any browser
- **JSON report** — machine-readable output of all findings

---

## ⚡ Setup in 3 Steps

### Step 1 — Download the external tools

You need four tools. Download each one and place the `.exe` files where you want them:

| Tool | What it does | Download |
|------|-------------|---------|
| **TrID** | Identifies file types | [mark0.net/soft-trid-e.html](https://mark0.net/soft-trid-e.html) |
| **Detect-It-Easy (diec)** | Detects packers, compilers, file types | [github.com/horsicq/DIE-engine](https://github.com/horsicq/DIE-engine/releases) |
| **Strings** | Extracts ASCII and Unicode strings | [learn.microsoft.com/sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/strings) |
| **FLOSS** | Recovers obfuscated/encoded strings | [github.com/mandiant/flare-floss](https://github.com/mandiant/flare-floss/releases) |

> **TrID note:** Also download `TrIDDefs.TRD` (the definitions file) from the same page and keep it in the same folder as `trid.exe`.
>
> **DIE note:** Keep the `db/` folder that comes with the DIE download alongside `diec.exe`.

---

### Step 2 — Edit the tool paths in the script

Open `malwelyzer.py` and find this block near the top:

```python
TOOL_PATHS = {
    "trid"   : r"C:\Tools\trid\trid.exe",
    "die"    : r"C:\Tools\die\diec.exe",
    "strings": r"C:\Tools\strings\strings.exe",
    "floss"  : r"C:\Tools\floss\floss.exe",
}
```

Replace each path with wherever you put the `.exe` files. The `r` before each string is important — keep it.

---

### Step 3 — Add your VirusTotal API key *(optional but recommended)*

Get a **free** API key at [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us), then paste it in:

```python
VIRUSTOTAL_API_KEY = "your_key_here"
```

If you skip this, everything still works — VirusTotal results will just show a "not configured" message.

---

## 🚀 Running It

```cmd
python malwelyzer.py suspicious.exe
```

That's it. The script will automatically install any missing Python libraries on first run, then perform the full analysis.

**Example output files generated:**
```
suspicious_analysis.json   ← full machine-readable report
suspicious_report.html     ← open this in your browser
```

---

## 🛠️ All Command Line Options

```
python malwelyzer.py <file> [options]
```

| Flag | Description |
|------|-------------|
| `--output FILE` / `-o FILE` | Custom path for the JSON report |
| `--html FILE` | Custom path for the HTML report |
| `--no-floss` | Skip FLOSS string recovery (faster for large files) |
| `--no-pe` | Skip PE structure analysis |
| `--no-yara` | Skip YARA rule scanning |
| `--no-vt` | Skip VirusTotal lookup |
| `--strings-only` | Just dump all extracted strings and exit |
| `--show-all-strings` | Print every extracted string to the terminal |

**Examples:**

```cmd
# Basic scan
python malwelyzer.py malware.exe

# Skip VirusTotal (faster, offline)
python malwelyzer.py sample.dll --no-vt

# Save reports to specific locations
python malwelyzer.py ransomware.bin --output C:\Reports\result.json --html C:\Reports\result.html

# Quick string dump only
python malwelyzer.py unknown.exe --strings-only

# Full scan skipping FLOSS (much faster on large files)
python malwelyzer.py bigfile.exe --no-floss
```

---

## 📦 Python Libraries

All Python libraries are **automatically installed** the first time you run the script. You don't need to install anything manually.

| Library | Purpose | Required |
|---------|---------|---------|
| `rich` | Beautiful terminal tables and coloured output | Auto-installed |
| `colorama` | Windows terminal colour support | Auto-installed |
| `pefile` | PE file structure parsing | Auto-installed |
| `yara-python` | YARA rule scanning engine | Auto-installed |
| `requests` | VirusTotal API calls | Auto-installed |

If auto-install fails for any reason you can install them manually:

```cmd
pip install rich colorama pefile yara-python requests
```

---

## 📊 What the HTML Report Looks Like

The HTML report is a self-contained dark-themed page you open in any browser. It includes:

- A header showing the filename, size, SHA256, MD5, and verdict badge (MALWARE / SUSPICIOUS / CLEAN)
- A threat score progress bar
- Every analysis section in organised, colour-coded tables
- VirusTotal engine detections table with a clickable link to the full VT report
- Malware type classification with a confidence bar chart and evidence list

No internet connection needed to view it — it's a single `.html` file.

---

## 🔍 What Counts as Suspicious

The script flags the following automatically:

**Suspicious Windows APIs**
```
VirtualAlloc, WriteProcessMemory, CreateRemoteThread,
SetWindowsHookEx, GetAsyncKeyState, URLDownloadToFile,
IsDebuggerPresent, NtQueryInformationProcess, LoadLibrary ...
```

**Suspicious String Patterns**
```
powershell, cmd.exe, wscript, mshta, rundll32, regsvr32,
schtasks, bcdedit, vssadmin, base64, xor, .onion,
HKEY_LOCAL_MACHINE\...\Run, autorun.inf, pastebin.com ...
```

**Network Indicators**
- Hardcoded IP addresses
- HTTP/HTTPS URLs
- Domain names (.com, .net, .onion, .ru, etc.)
- Email addresses

---

## 🎯 Built-in YARA Rules

| Rule | Detects |
|------|---------|
| `Ransomware_Keywords` | Encryption strings, bitcoin, ransom notes |
| `RAT_Keywords` | Keylogging, webcam, reverse shell, remote admin |
| `Banker_Keywords` | Credential theft, form grabbing, banking terms |
| `Dropper_Keywords` | Download and execute patterns |
| `Rootkit_Keywords` | Kernel hooks, SSDT, DKOM, process hiding |
| `Worm_Keywords` | Self-propagation, SMB, autorun |
| `Spyware_Keywords` | Clipboard, browser history, activity monitoring |
| `Packer_Signs` | UPX, Themida, VMProtect, MPRESS, ASPack |

---

## 🔒 VirusTotal Behaviour

The script handles all VirusTotal scenarios gracefully:

1. **Hash lookup first** — checks by SHA256 instantly, no upload needed if the file is already known
2. **Auto-upload fallback** — if the hash isn't found, uploads the file automatically
3. **Polls for completion** — waits up to 60 seconds for the analysis to finish
4. **Clear failure messages** — every error condition has a specific, readable message:

```
Could not retrieve VirusTotal results: No API key configured.
Could not retrieve VirusTotal results: Invalid API key.
Could not retrieve VirusTotal results: API rate limit reached. Try again later.
Could not retrieve VirusTotal results: No internet connection.
Could not retrieve VirusTotal results: File too large (X MB > 32 MB free-tier limit).
Could not retrieve VirusTotal results: Analysis did not complete in time.
```

---

## 📁 Recommended Folder Layout

```
C:\MalwareAnalysis\
│
├── analyze.py              ← this script
│
├── trid\
│   ├── trid.exe
│   └── TrIDDefs.TRD        ← required definitions file
│
├── die\
│   ├── diec.exe
│   └── db\                 ← required database folder
│
├── strings\
│   └── strings.exe
│
└── floss\
    └── floss.exe
```

---

## ⚠️ Disclaimer

This tool is intended for **malware research, forensics, and educational purposes only**. Always analyse suspicious files in an **isolated environment** (VM, sandbox) disconnected from your main network. The authors are not responsible for misuse.

---

## 📄 License

MIT License — free to use, modify, and distribute.
