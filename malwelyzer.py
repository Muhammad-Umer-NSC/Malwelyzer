#!/usr/bin/env python3
"""
==============================================================================
  MALWARE ANALYSIS SCRIPT  |  Windows Static Analysis Toolkit  v3.0
==============================================================================
  External tools (configure paths in TOOL_PATHS below):
    - trid.exe       : File type identification
    - diec.exe       : Detect-It-Easy (file type + packer detection)
    - strings.exe    : Sysinternals strings extractor
    - floss.exe      : FireEye FLOSS (obfuscated string extractor)

  Python libraries (auto-installed if missing):
    - rich           : Terminal tables and styling
    - colorama       : Windows colour support
    - pefile         : PE file parsing
    - yara-python    : YARA rule scanning
    - requests       : VirusTotal API calls
==============================================================================
"""

# ═════════════════════════════════════════════════════════════════════════════
#  AUTO-INSTALLER  –  runs before everything else
# ═════════════════════════════════════════════════════════════════════════════
import sys
import subprocess
import importlib.util

REQUIRED_PACKAGES = {
    "rich"    : "rich",
    "colorama": "colorama",
    "pefile"  : "pefile",
    "yara"    : "yara-python",
    "requests": "requests",
}

def _ensure_packages():
    missing = [
        (mod, pip) for mod, pip in REQUIRED_PACKAGES.items()
        if importlib.util.find_spec(mod) is None
    ]
    if not missing:
        return
    print("\n[SETUP] Missing libraries detected. Installing...\n")
    for mod, pip_name in missing:
        print(f"  -> Installing {pip_name} ...")
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", pip_name, "--quiet"],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode == 0:
                print(f"  OK  {pip_name} installed.")
            else:
                print(f"  FAIL  {pip_name}: {result.stderr.strip()}")
        except subprocess.TimeoutExpired:
            print(f"  FAIL  Timed out installing {pip_name}.")
        except Exception as e:
            print(f"  FAIL  {pip_name}: {e}")
    print("\n[SETUP] Done. Starting analysis...\n")

_ensure_packages()

# ═════════════════════════════════════════════════════════════════════════════
#  STANDARD IMPORTS
# ═════════════════════════════════════════════════════════════════════════════
import os
import json
import math
import time
import hashlib
import shutil
import argparse
import datetime
import collections
import re

try:
    from rich.console import Console
    from rich.table   import Table
    from rich.panel   import Panel
    from rich.text    import Text
    from rich.rule    import Rule
    from rich         import box as rbox
    from rich.markup  import escape
    HAS_RICH = True
    console  = Console(highlight=False)
except ImportError:
    HAS_RICH = False
    console  = None

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    RED    = Fore.RED    + Style.BRIGHT
    GREEN  = Fore.GREEN  + Style.BRIGHT
    YELLOW = Fore.YELLOW + Style.BRIGHT
    CYAN   = Fore.CYAN   + Style.BRIGHT
    RESET  = Style.RESET_ALL
    WHITE  = Fore.WHITE  + Style.BRIGHT
except ImportError:
    RED = GREEN = YELLOW = CYAN = RESET = WHITE = ""

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ═════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════
TOOL_PATHS = {
    "trid"   : r"C:\Tools\trid\05-trid\trid.exe",
    "die"    : r"C:\Tools\die\die\diec.exe",
    "strings": r"C:\Tools\Strings\strings.exe",
    "floss"  : r"C:\Tools\floss\floss.exe",
}

# Get a free API key at https://www.virustotal.com/gui/join-us
VIRUSTOTAL_API_KEY  = "7bc6b26bc60a7806f877e19180c6a27a852f3282482bd88e28b24855106b4d87"
VT_TIMEOUT          = 30
VT_MAX_FILE_SIZE    = 32 * 1024 * 1024   # 32 MB free-tier limit

TOOL_TIMEOUT            = 60
MIN_STRING_LEN          = 5
MALWARE_SCORE_THRESHOLD = 30

# ═════════════════════════════════════════════════════════════════════════════
#  YARA RULES
# ═════════════════════════════════════════════════════════════════════════════
EMBEDDED_YARA_RULES = r"""
rule Ransomware_Keywords {
    meta: description = "Common ransomware strings"
    strings:
        $r1  = "your files have been encrypted" nocase
        $r2  = "bitcoin" nocase
        $r3  = "decrypt" nocase
        $r4  = "ransom" nocase
        $r5  = "AES-256" nocase
        $r6  = "RSA-2048" nocase
        $r7  = "CryptoLocker" nocase
        $r8  = "WannaCry" nocase
        $r9  = "README_FOR_DECRYPT" nocase
        $r10 = "pay" nocase
    condition: 3 of them
}
rule RAT_Keywords {
    meta: description = "Remote Access Trojan indicators"
    strings:
        $r1  = "keylog" nocase
        $r2  = "screenshot" nocase
        $r3  = "webcam" nocase
        $r4  = "reverse shell" nocase
        $r5  = "cmd.exe" nocase
        $r6  = "RemoteAdmin" nocase
        $r7  = "upload" nocase
        $r8  = "download" nocase
        $r9  = "shell" nocase
        $r10 = "execute" nocase
        $r11 = "socket" nocase
    condition: 4 of them
}
rule Banker_Keywords {
    meta: description = "Banking Trojan / credential stealer indicators"
    strings:
        $b1 = "password" nocase
        $b2 = "credentials" nocase
        $b3 = "bank" nocase
        $b4 = "credit card" nocase
        $b5 = "login" nocase
        $b6 = "hook" nocase
        $b7 = "inject" nocase
        $b8 = "form grab" nocase
        $b9 = "steal" nocase
    condition: 4 of them
}
rule Dropper_Keywords {
    meta: description = "Dropper / downloader indicators"
    strings:
        $d1 = "URLDownloadToFile" nocase
        $d2 = "WinExec" nocase
        $d3 = "ShellExecute" nocase
        $d4 = "CreateProcess" nocase
        $d5 = "DropPath" nocase
        $d6 = "Temp" nocase
        $d7 = "WriteFile" nocase
        $d8 = "payload" nocase
    condition: 3 of them
}
rule Rootkit_Keywords {
    meta: description = "Rootkit indicators"
    strings:
        $rk1 = "NtQuerySystemInformation" nocase
        $rk2 = "ZwQuerySystemInformation" nocase
        $rk3 = "DKOM" nocase
        $rk4 = "hide process" nocase
        $rk5 = "hook" nocase
        $rk6 = "SSDT" nocase
        $rk7 = "ring0" nocase
        $rk8 = "kernel" nocase
    condition: 3 of them
}
rule Worm_Keywords {
    meta: description = "Worm / self-propagation indicators"
    strings:
        $w1 = "spreads" nocase
        $w2 = "replicate" nocase
        $w3 = "network share" nocase
        $w4 = "SMB" nocase
        $w5 = "autorun.inf" nocase
        $w6 = "mass mail" nocase
        $w7 = "propagate" nocase
    condition: 2 of them
}
rule Spyware_Keywords {
    meta: description = "Spyware / adware indicators"
    strings:
        $s1 = "track" nocase
        $s2 = "spy" nocase
        $s3 = "monitor" nocase
        $s4 = "clipboard" nocase
        $s5 = "browser history" nocase
        $s6 = "cookie" nocase
        $s7 = "ActivityLog" nocase
    condition: 3 of them
}
rule Packer_Signs {
    meta: description = "Common packer indicators"
    strings:
        $p1 = "UPX0"
        $p2 = "UPX1"
        $p3 = "MPRESS"
        $p4 = "Themida"
        $p5 = "VMProtect"
        $p6 = "PECompact"
        $p7 = "ASPack"
    condition: any of them
}
"""

SUSPICIOUS_APIS = [
    "VirtualAlloc","VirtualProtect","WriteProcessMemory","CreateRemoteThread",
    "OpenProcess","ReadProcessMemory","SetWindowsHookEx","GetAsyncKeyState",
    "RegSetValueEx","RegCreateKey","CreateService","NtUnmapViewOfSection",
    "IsDebuggerPresent","CheckRemoteDebuggerPresent","NtQueryInformationProcess",
    "GetTickCount","QueryPerformanceCounter","Sleep",
    "URLDownloadToFile","InternetOpen","InternetConnect","HttpSendRequest",
    "WinExec","ShellExecute","CreateProcess","LoadLibrary","GetProcAddress",
    "FindResource","SizeofResource","LoadResource","LockResource",
]

SUSPICIOUS_STRINGS_PATTERNS = [
    r"cmd\.exe", r"powershell", r"wscript", r"cscript", r"mshta",
    r"regsvr32", r"rundll32", r"schtasks", r"at\.exe",
    r"net user", r"net localgroup", r"netsh",
    r"taskkill", r"bcdedit", r"vssadmin", r"wbadmin",
    r"\.onion", r"pastebin\.com", r"raw\.githubusercontent",
    r"base64", r"xor", r"rot13",
    r"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    r"autorun\.inf", r"\\\\.\\pipe\\", r"\\\\.\\mailslot\\",
    r"http://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}",
]

# ═════════════════════════════════════════════════════════════════════════════
#  TERMINAL OUTPUT HELPERS
# ═════════════════════════════════════════════════════════════════════════════

def rprint(msg):
    if HAS_RICH: console.print(msg)
    else: print(msg)

def rinfo(msg):
    if HAS_RICH: console.print(f"  [cyan][[*]][/cyan] {msg}")
    else: print(f"  [*] {msg}")

def rok(msg):
    if HAS_RICH: console.print(f"  [bold green][[+]][/bold green] {msg}")
    else: print(f"  [+] {msg}")

def rwarn(msg):
    if HAS_RICH: console.print(f"  [bold yellow][[!]][/bold yellow] {msg}")
    else: print(f"  [!] {msg}")

def rbad(msg):
    if HAS_RICH: console.print(f"  [bold red][[-]][/bold red] {msg}")
    else: print(f"  [-] {msg}")

def section_header(title: str):
    if HAS_RICH:
        console.print()
        console.rule(f"[bold cyan] {title} [/bold cyan]", style="blue")
    else:
        print(f"\n{'─'*60}\n  {title}\n{'─'*60}")

def banner():
    if HAS_RICH:
        t = Text()
        t.append("  STATIC MALWARE ANALYSIS TOOLKIT  ", style="bold cyan")
        t.append("v3.0\n", style="bold white")
        t.append("  Hash  ·  Strings  ·  PE  ·  YARA  ·  VirusTotal  ·  HTML Report", style="dim cyan")
        console.print(Panel(t, border_style="cyan", padding=(1, 4)))
    else:
        print("=== STATIC MALWARE ANALYSIS TOOLKIT v3.0 ===")

# ═════════════════════════════════════════════════════════════════════════════
#  UTILITY
# ═════════════════════════════════════════════════════════════════════════════

def check_file(path: str) -> bool:
    if not path:           rbad("No file path provided."); return False
    if not os.path.exists(path):  rbad(f"File not found: {path}"); return False
    if not os.path.isfile(path):  rbad(f"Not a file: {path}"); return False
    if not os.access(path, os.R_OK): rbad(f"Permission denied: {path}"); return False
    if os.path.getsize(path) == 0:   rwarn(f"File is empty (0 bytes): {path}")
    return True

def resolve_tool(name: str):
    configured = TOOL_PATHS.get(name, name)
    if os.path.isfile(configured): return configured
    found = shutil.which(configured)
    if found: return found
    candidate = os.path.join(os.path.dirname(os.path.abspath(__file__)), configured)
    if os.path.isfile(candidate): return candidate
    return None

def run_tool(cmd: list, timeout: int = TOOL_TIMEOUT):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, errors="replace")
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        rwarn(f"Tool timed out ({timeout}s): {cmd[0]}"); return -1, "", "TIMEOUT"
    except FileNotFoundError:    return -2, "", "BINARY_NOT_FOUND"
    except PermissionError:      return -3, "", "PERMISSION_DENIED"
    except Exception as e:       return -99, "", str(e)

def _human_size(n: int) -> str:
    for unit in ("B","KB","MB","GB","TB"):
        if n < 1024: return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"

# ═════════════════════════════════════════════════════════════════════════════
#  1 ▸ METADATA & HASHES
# ═════════════════════════════════════════════════════════════════════════════

def get_hashes(path: str) -> dict:
    algos = {"MD5":hashlib.md5(),"SHA1":hashlib.sha1(),
             "SHA256":hashlib.sha256(),"SHA512":hashlib.sha512()}
    try:
        with open(path,"rb") as f:
            while chunk := f.read(65536):
                for h in algos.values(): h.update(chunk)
        return {n: h.hexdigest() for n, h in algos.items()}
    except (IOError, OSError) as e:
        rbad(f"Cannot hash file: {e}"); return {}

def get_file_metadata(path: str) -> dict:
    stat = os.stat(path)
    meta = {
        "path"      : os.path.abspath(path),
        "filename"  : os.path.basename(path),
        "size_bytes": stat.st_size,
        "size_human": _human_size(stat.st_size),
        "created"   : datetime.datetime.fromtimestamp(stat.st_ctime).isoformat(sep=" "),
        "modified"  : datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(sep=" "),
        "accessed"  : datetime.datetime.fromtimestamp(stat.st_atime).isoformat(sep=" "),
    }
    try:
        with open(path,"rb") as f: meta["magic_bytes"] = f.read(16).hex().upper()
    except Exception: meta["magic_bytes"] = "N/A"
    return meta

# ═════════════════════════════════════════════════════════════════════════════
#  2 ▸ ENTROPY
# ═════════════════════════════════════════════════════════════════════════════

def shannon_entropy(data: bytes) -> float:
    if not data: return 0.0
    c = collections.Counter(data); n = len(data)
    return round(-sum((v/n)*math.log2(v/n) for v in c.values()), 4)

def get_entropy(path: str) -> dict:
    result = {"overall":0.0,"verdict":"","packed_likely":False}
    try:
        with open(path,"rb") as f: data = f.read()
        result["overall"] = shannon_entropy(data)
        e = result["overall"]
        if e >= 7.2:   result["verdict"] = "VERY HIGH – strongly suggests packing/encryption"; result["packed_likely"] = True
        elif e >= 6.5: result["verdict"] = "HIGH – possible packing or compression"
        elif e >= 5.0: result["verdict"] = "MEDIUM – some compressed/encoded regions possible"
        else:          result["verdict"] = "LOW – likely plain executable"
    except Exception as e: rbad(f"Entropy failed: {e}")
    return result

# ═════════════════════════════════════════════════════════════════════════════
#  3 ▸ FILE TYPE DETECTION
# ═════════════════════════════════════════════════════════════════════════════

def run_trid(path: str) -> list:
    tool = resolve_tool("trid")
    if not tool: rwarn("TrID not found."); return []
    rc, out, _ = run_tool([tool, path])
    if rc < 0:   rwarn("TrID could not run."); return []
    return [l.strip() for l in out.splitlines() if "%" in l][:10]

def run_die(path: str) -> list:
    tool = resolve_tool("die")
    if not tool: rwarn("diec.exe not found."); return []
    rc, out, err = run_tool([tool, path])
    if rc < 0:   rwarn("DIE could not run."); return []
    return [l.strip() for l in (out+err).splitlines()
            if l.strip() and not l.strip().startswith("DetectItEasy")]

# ═════════════════════════════════════════════════════════════════════════════
#  4 ▸ STRINGS
# ═════════════════════════════════════════════════════════════════════════════

def run_strings(path: str) -> list:
    tool = resolve_tool("strings")
    if not tool: rwarn("strings.exe not found – using built-in extractor."); return _builtin_strings(path)
    rc, out, _ = run_tool([tool,"-accepteula","-n",str(MIN_STRING_LEN),path])
    if rc < 0:   rwarn("strings.exe failed – using built-in extractor."); return _builtin_strings(path)
    return [s.strip() for s in out.splitlines() if s.strip()]

def run_floss(path: str) -> dict:
    empty = {"static":[],"decoded":[],"stack":[]}
    tool  = resolve_tool("floss")
    if not tool: rwarn("FLOSS not found."); return empty
    rc, out, _ = run_tool([tool,"--no-progress",path], timeout=120)
    if rc < 0:  rwarn("FLOSS could not run."); return empty
    result, key = {"static":[],"decoded":[],"stack":[]}, None
    for line in out.splitlines():
        ls, low = line.strip(), line.strip().lower()
        if not ls: continue
        if "static ascii" in low or "static strings" in low: key = "static"
        elif "decoded strings" in low: key = "decoded"
        elif "stack strings"   in low: key = "stack"
        elif key and len(ls) >= MIN_STRING_LEN and not ls.startswith("["): result[key].append(ls)
    return result

def _builtin_strings(path: str) -> list:
    found = []
    try:
        with open(path,"rb") as f: data = f.read()
        cur = []
        for b in data:
            if 0x20 <= b < 0x7F: cur.append(chr(b))
            else:
                if len(cur) >= MIN_STRING_LEN: found.append("".join(cur))
                cur = []
        try:
            for chunk in re.split(r"[^\x20-\x7E]", data.decode("utf-16-le",errors="ignore")):
                if len(chunk) >= MIN_STRING_LEN: found.append(chunk)
        except Exception: pass
    except Exception as e: rbad(f"Built-in strings failed: {e}")
    return list(dict.fromkeys(found))

# ═════════════════════════════════════════════════════════════════════════════
#  5 ▸ PE ANALYSIS
# ═════════════════════════════════════════════════════════════════════════════

def analyze_pe(path: str):
    if not HAS_PEFILE: rwarn("pefile not installed – PE analysis skipped."); return None
    try: pe = pefile.PE(path)
    except pefile.PEFormatError as e: rinfo(f"Not a PE / corrupt PE: {e}"); return None
    except Exception as e: rbad(f"pefile error: {e}"); return None

    result = {}
    try:
        result["machine"]      = pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine,"Unknown")
        result["timestamp"]    = datetime.datetime.utcfromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat(sep=" ") + " UTC"
        result["subsystem"]    = pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem,"Unknown")
        result["is_dll"]       = bool(pe.FILE_HEADER.Characteristics & 0x2000)
        result["is_exe"]       = bool(pe.FILE_HEADER.Characteristics & 0x0002)
        result["num_sections"] = pe.FILE_HEADER.NumberOfSections
    except AttributeError: pass

    sections = []
    try:
        for s in pe.sections:
            name = s.Name.decode("utf-8",errors="replace").rstrip("\x00")
            ent  = shannon_entropy(s.get_data())
            sections.append({"name":name,"vaddr":hex(s.VirtualAddress),
                              "vsize":s.Misc_VirtualSize,"rawsize":s.SizeOfRawData,
                              "entropy":ent,"high_entropy":ent>=7.0})
    except Exception: pass
    result["sections"] = sections

    imports = {}
    try:
        if hasattr(pe,"DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode("utf-8",errors="replace")
                imports[dll] = [
                    imp.name.decode("utf-8",errors="replace") if imp.name else f"ord_{imp.ordinal}"
                    for imp in entry.imports
                ]
    except Exception: pass
    result["imports"] = imports

    exports = []
    try:
        if hasattr(pe,"DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name: exports.append(exp.name.decode("utf-8",errors="replace"))
    except Exception: pass
    result["exports"] = exports

    vi = {}
    try:
        if hasattr(pe,"VS_VERSIONINFO"):
            for v in pe.VS_VERSIONINFO:
                if hasattr(v,"StringTable"):
                    for st in v.StringTable:
                        for k, val in st.entries.items():
                            vi[k.decode(errors="replace")] = val.decode(errors="replace")
    except Exception: pass
    result["version_info"]  = vi
    result["has_tls"]       = hasattr(pe,"DIRECTORY_ENTRY_TLS")
    result["has_resources"] = hasattr(pe,"DIRECTORY_ENTRY_RESOURCE")
    try:
        ov = pe.get_overlay_data_start_offset()
        result["overlay_bytes"] = len(pe.get_overlay()) if ov else 0
    except Exception: result["overlay_bytes"] = 0
    pe.close()
    return result

# ═════════════════════════════════════════════════════════════════════════════
#  6 ▸ YARA
# ═════════════════════════════════════════════════════════════════════════════

def run_yara(path: str) -> list:
    if not HAS_YARA: rwarn("yara-python not installed – YARA scan skipped."); return []
    try:
        rules   = yara.compile(source=EMBEDDED_YARA_RULES)
        matches = rules.match(path)
        return [m.rule for m in matches]
    except yara.SyntaxError as e: rbad(f"YARA syntax error: {e}"); return []
    except Exception as e:        rbad(f"YARA error: {e}"); return []

# ═════════════════════════════════════════════════════════════════════════════
#  7 ▸ NETWORK INDICATORS & SUSPICIOUS STRINGS
# ═════════════════════════════════════════════════════════════════════════════

def extract_network_indicators(strings_list: list) -> dict:
    ind = {"ips":[],"domains":[],"urls":[],"emails":[]}
    ip_re     = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
    domain_re = re.compile(r"\b(?:[a-zA-Z0-9\-]+\.)+(?:com|net|org|io|ru|cn|pw|tk|xyz|onion|biz|info|top)\b",re.I)
    url_re    = re.compile(r"https?://[^\s\"'<>]+",re.I)
    email_re  = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
    for s in strings_list:
        for m in ip_re.findall(s):
            if m not in ind["ips"] and not m.startswith("127.") and m != "0.0.0.0": ind["ips"].append(m)
        for m in url_re.findall(s):
            if m not in ind["urls"]: ind["urls"].append(m)
        for m in email_re.findall(s):
            if m not in ind["emails"]: ind["emails"].append(m)
        for m in domain_re.findall(s):
            if m not in ind["domains"] and m not in ind["urls"]: ind["domains"].append(m)
    return ind

def find_suspicious_strings(strings_list: list) -> dict:
    combined = " ".join(strings_list)
    apis     = [a for a in SUSPICIOUS_APIS if a.lower() in combined.lower()]
    sus      = []
    for pat in SUSPICIOUS_STRINGS_PATTERNS:
        for s in strings_list:
            if re.search(pat, s, re.I): sus.append(s); break
    return {"suspicious_apis": apis, "suspicious_strings": sus[:30]}

# ═════════════════════════════════════════════════════════════════════════════
#  8 ▸ VIRUSTOTAL
# ═════════════════════════════════════════════════════════════════════════════

def virustotal_lookup(sha256: str, file_path: str) -> dict:
    FAIL = {"status":"error","message":"Could not retrieve VirusTotal results.","data":None}

    if not HAS_REQUESTS:
        FAIL["message"] = "Could not retrieve VirusTotal results: 'requests' library not available."
        return FAIL

    api_key = VIRUSTOTAL_API_KEY.strip()
    if not api_key or api_key == "YOUR_VIRUSTOTAL_API_KEY_HERE":
        FAIL["message"] = "Could not retrieve VirusTotal results: No API key configured. Add your key to VIRUSTOTAL_API_KEY."
        return FAIL

    headers = {"x-apikey": api_key}

    # Step 1: look up by hash
    try:
        rinfo("Querying VirusTotal by hash ...")
        resp = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256}",
                            headers=headers, timeout=VT_TIMEOUT)
        if resp.status_code == 200:
            return _parse_vt_response(resp.json())
        elif resp.status_code == 401:
            FAIL["message"] = "Could not retrieve VirusTotal results: Invalid API key."; return FAIL
        elif resp.status_code == 429:
            FAIL["message"] = "Could not retrieve VirusTotal results: API rate limit reached. Try again later."; return FAIL
        elif resp.status_code != 404:
            FAIL["message"] = f"Could not retrieve VirusTotal results: HTTP {resp.status_code}."; return FAIL
        rinfo("Hash not found on VirusTotal – attempting file upload ...")
    except requests.exceptions.ConnectionError:
        FAIL["message"] = "Could not retrieve VirusTotal results: No internet connection."; return FAIL
    except requests.exceptions.Timeout:
        FAIL["message"] = "Could not retrieve VirusTotal results: Connection timed out."; return FAIL
    except Exception as e:
        FAIL["message"] = f"Could not retrieve VirusTotal results: {e}"; return FAIL

    # Step 2: upload
    file_size = os.path.getsize(file_path)
    if file_size > VT_MAX_FILE_SIZE:
        FAIL["message"] = (f"Could not retrieve VirusTotal results: "
                           f"File too large ({_human_size(file_size)} > 32 MB free-tier limit).")
        return FAIL

    try:
        with open(file_path,"rb") as f:
            up = requests.post("https://www.virustotal.com/api/v3/files",
                               headers=headers,
                               files={"file":(os.path.basename(file_path), f)},
                               timeout=120)
        if up.status_code not in (200,201):
            FAIL["message"] = f"Could not retrieve VirusTotal results: Upload failed (HTTP {up.status_code})."; return FAIL

        analysis_id = up.json().get("data",{}).get("id","")
        if not analysis_id:
            FAIL["message"] = "Could not retrieve VirusTotal results: No analysis ID returned."; return FAIL

        rinfo("File uploaded. Waiting for analysis (up to 60s) ...")
        for _ in range(12):
            time.sleep(5)
            poll = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                                headers=headers, timeout=VT_TIMEOUT)
            if poll.status_code == 200:
                status = poll.json().get("data",{}).get("attributes",{}).get("status","")
                if status == "completed":
                    fr = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256}",
                                      headers=headers, timeout=VT_TIMEOUT)
                    if fr.status_code == 200: return _parse_vt_response(fr.json())

        FAIL["message"] = "Could not retrieve VirusTotal results: Analysis did not complete in time."; return FAIL

    except requests.exceptions.ConnectionError:
        FAIL["message"] = "Could not retrieve VirusTotal results: No internet connection during upload."; return FAIL
    except requests.exceptions.Timeout:
        FAIL["message"] = "Could not retrieve VirusTotal results: Upload timed out."; return FAIL
    except Exception as e:
        FAIL["message"] = f"Could not retrieve VirusTotal results: {e}"; return FAIL


def _parse_vt_response(data: dict) -> dict:
    try:
        attrs   = data["data"]["attributes"]
        stats   = attrs.get("last_analysis_stats",{})
        sha256  = attrs.get("sha256","N/A")
        results = attrs.get("last_analysis_results",{})
        detections = [
            {"engine":eng,"result":res.get("result","N/A"),"category":res.get("category","N/A")}
            for eng, res in results.items()
            if res.get("category") in ("malicious","suspicious")
        ]
        return {
            "status"          : "success",
            "message"         : "OK",
            "sha256"          : sha256,
            "meaningful_name" : attrs.get("meaningful_name","N/A"),
            "type_description": attrs.get("type_description","N/A"),
            "malicious"       : stats.get("malicious",0),
            "suspicious"      : stats.get("suspicious",0),
            "undetected"      : stats.get("undetected",0),
            "total_engines"   : sum(stats.values()),
            "detections"      : detections[:30],
            "vt_link"         : f"https://www.virustotal.com/gui/file/{sha256}",
            "scan_date"       : str(attrs.get("last_analysis_date","N/A")),
        }
    except Exception as e:
        return {"status":"error","message":f"Could not parse VirusTotal results: {e}","data":None}

# ═════════════════════════════════════════════════════════════════════════════
#  9 ▸ CLASSIFICATION
# ═════════════════════════════════════════════════════════════════════════════

def classify_malware(yara_matches, suspicious, entropy, pe_data, network_indicators) -> dict:
    scores  = collections.defaultdict(int)
    reasons = collections.defaultdict(list)

    yara_map = {
        "Ransomware_Keywords": ("Ransomware",                50),
        "RAT_Keywords"       : ("Remote Access Trojan (RAT)",50),
        "Banker_Keywords"    : ("Banking Trojan",            50),
        "Dropper_Keywords"   : ("Dropper / Downloader",      40),
        "Rootkit_Keywords"   : ("Rootkit",                   50),
        "Worm_Keywords"      : ("Worm",                      40),
        "Spyware_Keywords"   : ("Spyware / Adware",          35),
        "Packer_Signs"       : ("Packed Malware",            20),
    }
    for rule in yara_matches:
        if rule in yara_map:
            t, p = yara_map[rule]; scores[t] += p; reasons[t].append(f"YARA rule matched: {rule}")

    if entropy.get("packed_likely"):
        scores["Packed Malware"] += 25; reasons["Packed Malware"].append(f"Very high entropy ({entropy['overall']})")

    api_set       = set(suspicious.get("suspicious_apis",[]))
    keylog_apis   = {"GetAsyncKeyState","SetWindowsHookEx"}
    inject_apis   = {"WriteProcessMemory","CreateRemoteThread","OpenProcess","VirtualAlloc","VirtualProtect"}
    download_apis = {"URLDownloadToFile","InternetOpen","InternetConnect","HttpSendRequest"}
    evasion_apis  = {"IsDebuggerPresent","CheckRemoteDebuggerPresent","NtQueryInformationProcess","GetTickCount","Sleep"}

    if api_set & keylog_apis:   scores["Keylogger / Spyware"]   += 30; reasons["Keylogger / Spyware"].append("Keylogging APIs: " + str(api_set & keylog_apis))
    if api_set & inject_apis:   scores["Process Injector / RAT"] += 30; reasons["Process Injector / RAT"].append("Injection APIs: " + str(api_set & inject_apis))
    if api_set & download_apis: scores["Dropper / Downloader"]   += 25; reasons["Dropper / Downloader"].append("Network download APIs detected")
    if api_set & evasion_apis:  scores["Evasive Malware"]        += 20; reasons["Evasive Malware"].append("Anti-analysis APIs: " + str(api_set & evasion_apis))

    if network_indicators.get("ips"):
        scores["Command & Control (C2)"] += 20; reasons["Command & Control (C2)"].append(f"Hardcoded IPs: {network_indicators['ips'][:3]}")
    if any(".onion" in d for d in network_indicators.get("domains",[])):
        scores["Ransomware"] += 30; reasons["Ransomware"].append(".onion domain found (Tor C2)")

    if pe_data:
        if pe_data.get("has_tls"):
            scores["Evasive Malware"] += 10; reasons["Evasive Malware"].append("TLS callbacks (anti-debug)")
        if pe_data.get("overlay_bytes",0) > 1024:
            scores["Dropper / Downloader"] += 15; reasons["Dropper / Downloader"].append(f"PE overlay: {pe_data['overlay_bytes']} bytes")
        for sec in pe_data.get("sections",[]):
            if sec.get("high_entropy"):
                scores["Packed Malware"] += 10; reasons["Packed Malware"].append(f"Section '{sec['name']}' entropy={sec['entropy']}"); break

    total     = sum(scores.values())
    top_types = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    return {
        "is_malware"   : total >= MALWARE_SCORE_THRESHOLD,
        "total_score"  : total,
        "threshold"    : MALWARE_SCORE_THRESHOLD,
        "malware_types": top_types,
        "primary_type" : top_types[0][0] if top_types else "Unknown",
        "reasons"      : dict(reasons),
    }

# ═════════════════════════════════════════════════════════════════════════════
#  TERMINAL PRINT FUNCTIONS  (rich tables)
# ═════════════════════════════════════════════════════════════════════════════

def _simple_table() -> "Table":
    t = Table(show_header=False, box=rbox.SIMPLE, padding=(0,1))
    t.add_column("Key",   style="bold cyan", no_wrap=True)
    t.add_column("Value", style="white")
    return t

def print_metadata(meta, hashes):
    section_header("FILE METADATA & HASHES")
    if HAS_RICH:
        t = _simple_table()
        t.add_row("File",        meta["filename"])
        t.add_row("Full path",   meta["path"])
        t.add_row("Size",        f"{meta['size_bytes']:,} bytes  ({meta['size_human']})")
        t.add_row("Created",     meta["created"])
        t.add_row("Modified",    meta["modified"])
        t.add_row("Magic bytes", meta["magic_bytes"])
        for k,v in hashes.items(): t.add_row(k, v)
        console.print(t)
    else:
        for k,v in {**meta,**hashes}.items(): print(f"  {k:<20}{v}")

def print_entropy(ent):
    section_header("ENTROPY ANALYSIS")
    e   = ent["overall"]
    col = "bold red" if ent["packed_likely"] else ("yellow" if e>=6.5 else "green")
    if HAS_RICH:
        t = _simple_table()
        t.add_row("Overall entropy", f"[{col}]{e}[/{col}]  / 8.0 max")
        t.add_row("Verdict",         f"[{col}]{ent['verdict']}[/{col}]")
        console.print(t)
    else: print(f"  Entropy: {e}  –  {ent['verdict']}")

def print_file_types(trid, die):
    section_header("FILE TYPE DETECTION")
    if HAS_RICH:
        if trid:
            t = Table(title="TrID Results", box=rbox.ROUNDED, border_style="cyan", show_header=False, padding=(0,1))
            t.add_column("Result", style="cyan")
            for l in trid: t.add_row(l)
            console.print(t)
        else: rwarn("TrID: no results.")
        if die:
            t = Table(title="Detect-It-Easy Results", box=rbox.ROUNDED, border_style="cyan", show_header=False, padding=(0,1))
            t.add_column("Result", style="cyan")
            for l in die: t.add_row(l)
            console.print(t)
        else: rwarn("DIE: no results.")
    else:
        print("  TrID:", trid); print("  DIE:", die)

def print_strings_summary(all_strings, floss_data, suspicious, net):
    section_header("STRINGS ANALYSIS")
    if not HAS_RICH:
        print(f"  Total strings: {len(all_strings)}")
        for a in suspicious["suspicious_apis"]: print(f"  [API] {a}")
        return

    s = _simple_table()
    s.add_row("Total strings extracted", str(len(all_strings)))
    s.add_row("FLOSS decoded strings",   str(len(floss_data.get("decoded",[]))))
    s.add_row("FLOSS stack strings",     str(len(floss_data.get("stack",[]))))
    console.print(s)

    def _mini(title, col_name, style, items, max_i=15):
        if not items: return
        t = Table(title=title, box=rbox.ROUNDED, border_style=style.replace("bold ",""),
                  show_header=False, padding=(0,1))
        t.add_column(col_name, style=style, no_wrap=False)
        for i in items[:max_i]: t.add_row(escape(str(i))[:120])
        console.print(t)

    _mini("[bold red]Suspicious Windows APIs[/bold red]",       "API",    "bold red",    suspicious["suspicious_apis"])
    _mini("[bold yellow]Suspicious String Patterns[/bold yellow]","String","yellow",     suspicious["suspicious_strings"])
    _mini("[bold red]Hardcoded IP Addresses[/bold red]",         "IP",    "bold red",    net["ips"], 10)
    _mini("[bold red]URLs Found[/bold red]",                     "URL",   "red",         net["urls"], 10)
    _mini("[bold yellow]Domains Found[/bold yellow]",            "Domain","yellow",      net["domains"], 10)
    _mini("[bold yellow]Email Addresses[/bold yellow]",          "Email", "yellow",      net["emails"], 5)
    _mini("[bold red]FLOSS Decoded (Obfuscated) Strings[/bold red]","String","bold red", floss_data.get("decoded",[]))

def print_pe_info(pe_data):
    if not pe_data: return
    section_header("PE FILE ANALYSIS")
    if not HAS_RICH:
        for k,v in pe_data.items():
            if k not in ("sections","imports","exports","version_info"): print(f"  {k:<22}{v}")
        return

    t = _simple_table()
    t.add_row("Architecture", str(pe_data.get("machine","N/A")))
    t.add_row("Compile time", str(pe_data.get("timestamp","N/A")))
    t.add_row("Subsystem",    str(pe_data.get("subsystem","N/A")))
    t.add_row("Is DLL",       str(pe_data.get("is_dll","N/A")))
    t.add_row("Sections",     str(pe_data.get("num_sections","N/A")))
    t.add_row("TLS callbacks",str(pe_data.get("has_tls","N/A")))
    t.add_row("Resources",    str(pe_data.get("has_resources","N/A")))
    t.add_row("Overlay data", f"{pe_data.get('overlay_bytes',0):,} bytes")
    console.print(t)

    if pe_data.get("sections"):
        st = Table(title="PE Sections", box=rbox.ROUNDED, border_style="cyan", padding=(0,1))
        st.add_column("Name",    style="cyan",  no_wrap=True)
        st.add_column("VAddr",   style="white", no_wrap=True)
        st.add_column("VSize",   style="white", justify="right")
        st.add_column("RawSize", style="white", justify="right")
        st.add_column("Entropy", justify="right")
        st.add_column("Flag",    style="bold red")
        for s in pe_data["sections"]:
            ec = "bold red" if s["high_entropy"] else "green"
            st.add_row(s["name"],s["vaddr"],str(s["vsize"]),str(s["rawsize"]),
                       f"[{ec}]{s['entropy']}[/{ec}]",
                       "HIGH ENTROPY" if s["high_entropy"] else "")
        console.print(st)

    if pe_data.get("version_info"):
        vt = Table(title="Version Info", box=rbox.ROUNDED, border_style="cyan", padding=(0,1))
        vt.add_column("Key",   style="bold cyan", no_wrap=True)
        vt.add_column("Value", style="white")
        for k,v in list(pe_data["version_info"].items())[:8]: vt.add_row(k,v)
        console.print(vt)

    if pe_data.get("imports"):
        it = Table(title=f"Imported DLLs ({len(pe_data['imports'])})",
                   box=rbox.ROUNDED, border_style="cyan", padding=(0,1))
        it.add_column("DLL",     style="cyan",  no_wrap=True)
        it.add_column("Imports", style="white", justify="right")
        for dll, funcs in list(pe_data["imports"].items())[:12]: it.add_row(dll, str(len(funcs)))
        console.print(it)

def print_yara_results(matches):
    section_header("YARA SCAN RESULTS")
    if HAS_RICH:
        if matches:
            t = Table(title=f"[bold red]{len(matches)} YARA Rule(s) Matched[/bold red]",
                      box=rbox.ROUNDED, border_style="red", show_header=False, padding=(0,1))
            t.add_column("Rule", style="bold red")
            for m in matches: t.add_row(m)
            console.print(t)
        else: rok("No YARA rules matched.")
    else:
        for m in matches: print(f"  [YARA] {m}")
        if not matches: print("  [+] No YARA matches")

def print_vt_results(vt):
    section_header("VIRUSTOTAL RESULTS")
    if vt["status"] == "error":
        rwarn(vt["message"]); return
    if vt["status"] == "skipped":
        rinfo("VirusTotal lookup was skipped (use without --no-vt to enable)."); return
    if not HAS_RICH:
        print(f"  Detections: {vt['malicious']}/{vt['total_engines']}"); return

    t = _simple_table()
    t.add_row("Scan date",     str(vt.get("scan_date","N/A")))
    t.add_row("File name",     str(vt.get("meaningful_name","N/A")))
    t.add_row("Type",          str(vt.get("type_description","N/A")))
    dc = "bold red" if vt["malicious"]>5 else ("yellow" if vt["malicious"]>0 else "green")
    t.add_row("Malicious",     f"[{dc}]{vt['malicious']}[/{dc}]")
    t.add_row("Suspicious",    f"[yellow]{vt['suspicious']}[/yellow]")
    t.add_row("Undetected",    f"[green]{vt['undetected']}[/green]")
    t.add_row("Total engines", str(vt["total_engines"]))
    t.add_row("VT Report",     f"[link={vt['vt_link']}][cyan]{vt['vt_link']}[/cyan][/link]")
    console.print(t)

    if vt.get("detections"):
        dt = Table(title="[bold red]Engine Detections[/bold red]",
                   box=rbox.ROUNDED, border_style="red", padding=(0,1))
        dt.add_column("Engine",   style="cyan",   no_wrap=True)
        dt.add_column("Result",   style="red",    no_wrap=False)
        dt.add_column("Category", style="yellow", no_wrap=True)
        for d in vt["detections"]: dt.add_row(d["engine"], escape(str(d["result"])), d["category"])
        console.print(dt)

def print_verdict(classification):
    section_header("MALWARE CLASSIFICATION VERDICT")
    score  = classification["total_score"]
    thresh = classification["threshold"]
    is_mal = classification["is_malware"]

    if HAS_RICH:
        if is_mal:             style, label = "bold red",    "LIKELY MALWARE"
        elif score>=thresh//2: style, label = "bold yellow", "SUSPICIOUS"
        else:                  style, label = "bold green",  "LIKELY CLEAN"

        vt = Text()
        vt.append(f"\n  VERDICT  :  {label}\n", style=style)
        vt.append(f"  Score    :  {score} / {thresh} (threshold)\n", style=style)
        if is_mal and classification.get("primary_type"):
            vt.append(f"  Primary  :  {classification['primary_type']}\n", style=style)
        console.print(Panel(vt, border_style=style.replace("bold ",""), padding=(0,2)))

        if classification["malware_types"]:
            tt = Table(title="Threat Scores by Type", box=rbox.ROUNDED, border_style="yellow", padding=(0,1))
            tt.add_column("Type",  style="bold white", no_wrap=True)
            tt.add_column("Score", style="white",      justify="right")
            tt.add_column("Bar",   no_wrap=True)
            for mtype, pts in classification["malware_types"][:6]:
                bar = "█" * min(int(pts/3),30)
                col = "red" if pts>=thresh else "yellow"
                tt.add_row(mtype, str(pts), f"[{col}]{bar}[/{col}]")
            console.print(tt)

        if classification["reasons"]:
            rt = Table(title="Evidence & Reasons", box=rbox.ROUNDED, border_style="yellow", padding=(0,1))
            rt.add_column("Type",     style="bold cyan", no_wrap=True)
            rt.add_column("Evidence", style="yellow")
            for mtype, evlist in classification["reasons"].items():
                for ev in evlist: rt.add_row(mtype, escape(ev))
            console.print(rt)
    else:
        verdict = "LIKELY MALWARE" if is_mal else ("SUSPICIOUS" if score>=thresh//2 else "LIKELY CLEAN")
        print(f"\n  VERDICT: {verdict}  Score: {score}/{thresh}\n")

# ═════════════════════════════════════════════════════════════════════════════
#  HTML REPORT
# ═════════════════════════════════════════════════════════════════════════════

def _esc(s: str) -> str:
    return (str(s).replace("&","&amp;").replace("<","&lt;")
                  .replace(">","&gt;").replace('"',"&quot;"))

def generate_html_report(report: dict, out_path: str):
    meta      = report.get("metadata",{})
    hashes    = meta.get("hashes",{})
    ent       = report.get("entropy",{})
    ft        = report.get("file_types",{})
    sus       = report.get("suspicious_strings",{})
    net       = report.get("network_indicators",{})
    pe        = report.get("pe_analysis") or {}
    yara_hits = report.get("yara_matches",[])
    clf       = report.get("classification",{})
    vt        = report.get("virustotal",{})
    strs      = report.get("strings",{})

    is_mal = clf.get("is_malware",False)
    score  = clf.get("total_score",0)
    thresh = clf.get("threshold",30)

    if is_mal:             verdict_cls, verdict_txt = "verdict-malware",   "LIKELY MALWARE"
    elif score>=thresh//2: verdict_cls, verdict_txt = "verdict-suspicious","SUSPICIOUS"
    else:                  verdict_cls, verdict_txt = "verdict-clean",     "LIKELY CLEAN"

    def kv(k, v, cls=""):
        c = f' class="{cls}"' if cls else ""
        return f"<tr><td class='kk'>{_esc(k)}</td><td{c}>{_esc(str(v))}</td></tr>"

    def badge(items, colour="red"):
        if not items: return '<span class="dim">None found</span>'
        return " ".join(f'<span class="badge b-{colour}">{_esc(i)}</span>' for i in items)

    def str_list(items):
        return "".join(f'<div class="si">{_esc(str(s)[:160])}</div>' for s in items)

    # Metadata
    meta_rows  = (kv("Filename",  meta.get("filename","N/A")) +
                  kv("Full path", meta.get("path","N/A")) +
                  kv("Size",      f"{meta.get('size_bytes',0):,} bytes ({meta.get('size_human','')})") +
                  kv("Created",   meta.get("created","N/A")) +
                  kv("Modified",  meta.get("modified","N/A")) +
                  kv("Magic",     meta.get("magic_bytes","N/A")))
    hash_rows  = "".join(kv(k,v) for k,v in hashes.items())

    # Entropy
    e_val = ent.get("overall",0)
    e_cls = "red" if ent.get("packed_likely") else ("yellow" if e_val>=6.5 else "green")
    ent_rows = kv("Overall entropy", f"{e_val} / 8.0 max", e_cls) + kv("Verdict", ent.get("verdict","N/A"), e_cls)

    # File types
    trid_rows = "".join(f"<tr><td>{_esc(l)}</td></tr>" for l in ft.get("trid",[])) or "<tr><td class='dim'>No results</td></tr>"
    die_rows  = "".join(f"<tr><td>{_esc(l)}</td></tr>" for l in ft.get("die",[]))  or "<tr><td class='dim'>No results</td></tr>"

    # PE
    pe_basic = ""
    if pe:
        pe_basic = (kv("Architecture", pe.get("machine","N/A")) +
                    kv("Compile time", pe.get("timestamp","N/A")) +
                    kv("Subsystem",    str(pe.get("subsystem","N/A"))) +
                    kv("Is DLL",       str(pe.get("is_dll","N/A"))) +
                    kv("Sections",     str(pe.get("num_sections","N/A"))) +
                    kv("TLS callbacks",str(pe.get("has_tls","N/A")), "yellow" if pe.get("has_tls") else "") +
                    kv("Has resources",str(pe.get("has_resources","N/A"))) +
                    kv("Overlay data", f"{pe.get('overlay_bytes',0):,} bytes", "yellow" if pe.get("overlay_bytes",0)>1024 else ""))

    pe_sec_html = ""
    if pe.get("sections"):
        rows = "".join(
            f"<tr><td>{_esc(s['name'])}</td><td>{_esc(s['vaddr'])}</td>"
            f"<td>{s['vsize']}</td><td>{s['rawsize']}</td>"
            f"<td class=\"{'red' if s['high_entropy'] else ''}\">{s['entropy']}</td>"
            f"<td>{'HIGH' if s['high_entropy'] else ''}</td></tr>"
            for s in pe["sections"])
        pe_sec_html = f"""<h3>Sections</h3>
        <table class="dt"><thead><tr><th>Name</th><th>VAddr</th><th>VSize</th><th>RawSize</th><th>Entropy</th><th>Flag</th></tr></thead>
        <tbody>{rows}</tbody></table>"""

    pe_imp_html = ""
    if pe.get("imports"):
        rows = "".join(f"<tr><td>{_esc(dll)}</td><td>{len(f)}</td></tr>"
                       for dll,f in list(pe["imports"].items())[:15])
        pe_imp_html = f"""<h3>Imported DLLs</h3>
        <table class="dt"><thead><tr><th>DLL</th><th>Import Count</th></tr></thead>
        <tbody>{rows}</tbody></table>"""

    # YARA
    yara_html = badge(yara_hits,"red") if yara_hits else '<span class="badge b-green">No rules matched</span>'

    # VirusTotal
    if vt.get("status") == "success":
        det = vt.get("malicious",0); tot = vt.get("total_engines",0)
        dc  = "red" if det>5 else ("yellow" if det>0 else "green")
        vt_rows = (kv("Scan date",    vt.get("scan_date","N/A")) +
                   kv("File name",    vt.get("meaningful_name","N/A")) +
                   kv("Type",         vt.get("type_description","N/A")) +
                   kv("Malicious",    f"{det} / {tot}", dc) +
                   kv("Suspicious",   str(vt.get("suspicious",0))) +
                   kv("Undetected",   str(vt.get("undetected",0))))
        vt_link = f'<a class="vtlink" href="{_esc(vt["vt_link"])}" target="_blank">View full VirusTotal report ↗</a>'
        det_rows = "".join(f"<tr><td>{_esc(d['engine'])}</td><td class='red'>{_esc(str(d['result']))}</td><td>{_esc(d['category'])}</td></tr>"
                           for d in vt.get("detections",[]))
        vt_det_html = (f"""<h3>Engine Detections</h3>
        <table class="dt"><thead><tr><th>Engine</th><th>Result</th><th>Category</th></tr></thead>
        <tbody>{det_rows}</tbody></table>""" if det_rows else "")
    else:
        vt_rows     = f"<tr><td colspan='2' class='dim'>{_esc(vt.get('message','VirusTotal data unavailable.'))}</td></tr>"
        vt_link     = ""
        vt_det_html = ""

    # Classification
    type_rows = ""
    for mtype, pts in clf.get("malware_types",[])[:6]:
        bw  = min(int(pts/2),100)
        bc  = "#e74c3c" if pts>=thresh else "#f39c12"
        type_rows += f"""<tr><td>{_esc(mtype)}</td><td>{pts}</td>
        <td><div class="bar-bg"><div class="bar-f" style="width:{bw}%;background:{bc}"></div></div></td></tr>"""

    ev_rows = "".join(f"<tr><td>{_esc(t)}</td><td>{_esc(e)}</td></tr>"
                      for t, evl in clf.get("reasons",{}).items() for e in evl)

    # String sections
    sus_apis_html = badge(sus.get("suspicious_apis",[]),"red")
    sus_str_html  = str_list(sus.get("suspicious_strings",[])[:20])
    floss_html    = str_list(strs.get("floss_decoded",[])[:20])
    net_ip_html   = badge(net.get("ips",[])[:15],"red")
    net_url_html  = str_list(net.get("urls",[])[:15])
    net_dom_html  = badge(net.get("domains",[])[:15],"yellow")

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Analysis Report – {_esc(meta.get('filename',''))}</title>
<style>
:root{{
  --bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--bd:#30363d;
  --tx:#e6edf3;--dim:#7d8590;
  --cy:#39d0d8;--gr:#3fb950;--ye:#d29922;--re:#f85149;--pu:#a371f7;--bl:#58a6ff;
}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--tx);line-height:1.6}}

/* Header */
.hdr{{background:linear-gradient(135deg,#0d1117,#1a1f2e 50%,#0d1117);border-bottom:1px solid var(--bd);padding:44px 60px 36px;position:relative;overflow:hidden}}
.hdr::before{{content:'';position:absolute;top:-60px;left:-60px;width:300px;height:300px;background:radial-gradient(circle,rgba(57,208,216,.12),transparent 70%)}}
.hdr::after{{content:'';position:absolute;bottom:-80px;right:-40px;width:400px;height:400px;background:radial-gradient(circle,rgba(163,113,247,.08),transparent 70%)}}
.hdr-top{{display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:20px;position:relative;z-index:1}}
.brand{{display:flex;align-items:center;gap:16px}}
.brand-icon{{width:52px;height:52px;background:linear-gradient(135deg,var(--cy),var(--pu));border-radius:13px;display:flex;align-items:center;justify-content:center;font-size:24px}}
.brand-text h1{{font-size:1.5rem;font-weight:700;color:var(--tx)}}
.brand-text p{{font-size:.82rem;color:var(--dim);margin-top:2px}}
.vbadge{{padding:9px 22px;border-radius:50px;font-weight:700;font-size:.95rem;letter-spacing:.4px;position:relative;z-index:1}}
.verdict-malware{{background:rgba(248,81,73,.15);border:2px solid var(--re);color:var(--re)}}
.verdict-suspicious{{background:rgba(210,153,34,.15);border:2px solid var(--ye);color:var(--ye)}}
.verdict-clean{{background:rgba(63,185,80,.15);border:2px solid var(--gr);color:var(--gr)}}
.hdr-file{{margin-top:26px;padding:16px 20px;background:rgba(255,255,255,.04);border:1px solid var(--bd);border-radius:10px;display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:12px;position:relative;z-index:1}}
.fi{{display:flex;flex-direction:column;gap:3px}}
.fi .lb{{font-size:.7rem;color:var(--dim);text-transform:uppercase;letter-spacing:.8px}}
.fi .vl{{font-size:.88rem;font-family:monospace;word-break:break-all}}

/* Layout */
.content{{max-width:1180px;margin:0 auto;padding:36px 36px 80px}}
.grid2{{display:grid;grid-template-columns:1fr 1fr;gap:22px}}
@media(max-width:780px){{.grid2{{grid-template-columns:1fr}}}}

/* Score */
.score-box{{margin-bottom:28px;padding:22px 26px;background:var(--bg2);border:1px solid var(--bd);border-radius:12px}}
.score-lbl{{display:flex;justify-content:space-between;margin-bottom:10px;font-size:.88rem}}
.score-track{{height:10px;background:var(--bg3);border-radius:99px;overflow:hidden}}
.score-fill{{height:100%;border-radius:99px}}

/* Card / Section */
.card{{margin-bottom:22px;background:var(--bg2);border:1px solid var(--bd);border-radius:12px;overflow:hidden}}
.card h2{{padding:13px 20px;font-size:.78rem;font-weight:600;text-transform:uppercase;letter-spacing:1.2px;color:var(--cy);background:rgba(57,208,216,.06);border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:8px}}
.card h2::before{{content:'';display:inline-block;width:3px;height:13px;background:var(--cy);border-radius:2px}}
.card h3{{padding:12px 20px 5px;font-size:.76rem;color:var(--dim);text-transform:uppercase;letter-spacing:.7px}}

/* Tables */
.dt{{width:100%;border-collapse:collapse;font-size:.86rem}}
.dt th{{padding:9px 20px;text-align:left;font-size:.72rem;font-weight:600;color:var(--dim);text-transform:uppercase;letter-spacing:.7px;background:rgba(255,255,255,.03);border-bottom:1px solid var(--bd)}}
.dt td{{padding:8px 20px;border-bottom:1px solid rgba(48,54,61,.5);vertical-align:top}}
.dt tbody tr:last-child td{{border-bottom:none}}
.dt tbody tr:hover{{background:rgba(255,255,255,.02)}}
.kk{{color:var(--dim);font-size:.8rem;white-space:nowrap;width:190px}}
.red{{color:var(--re)!important;font-weight:600}}
.yellow{{color:var(--ye)!important;font-weight:600}}
.green{{color:var(--gr)!important;font-weight:600}}
.dim{{color:var(--dim);font-style:italic}}

/* Badges */
.badge{{display:inline-block;padding:3px 10px;border-radius:50px;font-size:.76rem;font-weight:600;margin:2px}}
.b-red{{background:rgba(248,81,73,.15);color:var(--re);border:1px solid rgba(248,81,73,.4)}}
.b-yellow{{background:rgba(210,153,34,.15);color:var(--ye);border:1px solid rgba(210,153,34,.4)}}
.b-green{{background:rgba(63,185,80,.15);color:var(--gr);border:1px solid rgba(63,185,80,.4)}}

/* Bar */
.bar-bg{{background:var(--bg3);border-radius:4px;height:8px}}
.bar-f{{height:8px;border-radius:4px}}

/* String item */
.si{{padding:5px 20px;font-family:monospace;font-size:.8rem;border-bottom:1px solid rgba(48,54,61,.4);word-break:break-all;color:var(--dim)}}
.si:last-child{{border-bottom:none}}

/* VT link */
.vtlink{{display:inline-block;margin:6px 20px 14px;padding:7px 16px;background:rgba(57,208,216,.1);border:1px solid rgba(57,208,216,.3);border-radius:8px;color:var(--cy);text-decoration:none;font-size:.83rem;font-weight:600}}
.vtlink:hover{{background:rgba(57,208,216,.2)}}

/* Pad */
.pad{{padding:12px 20px}}

/* Footer */
.foot{{text-align:center;padding:28px;color:var(--dim);font-size:.78rem;border-top:1px solid var(--bd)}}
</style>
</head>
<body>

<div class="hdr">
  <div class="hdr-top">
    <div class="brand">
      <div class="brand-icon">&#128269;</div>
      <div class="brand-text">
        <h1>Malware Analysis Report</h1>
        <p>Static Analysis Toolkit v3.0 &nbsp;&middot;&nbsp; {_esc(now)}</p>
      </div>
    </div>
    <div class="vbadge {verdict_cls}">{verdict_txt}</div>
  </div>
  <div class="hdr-file">
    <div class="fi"><span class="lb">Filename</span><span class="vl">{_esc(meta.get('filename','N/A'))}</span></div>
    <div class="fi"><span class="lb">File Size</span><span class="vl">{_esc(meta.get('size_human','N/A'))} ({meta.get('size_bytes',0):,} bytes)</span></div>
    <div class="fi"><span class="lb">SHA256</span><span class="vl">{_esc(hashes.get('SHA256','N/A'))}</span></div>
    <div class="fi"><span class="lb">MD5</span><span class="vl">{_esc(hashes.get('MD5','N/A'))}</span></div>
  </div>
</div>

<div class="content">

  <!-- Score -->
  <div class="score-box">
    <div class="score-lbl">
      <span>Threat Score</span>
      <span><b style="color:{'var(--re)' if is_mal else 'var(--ye)' if score>=thresh//2 else 'var(--gr)'}">{score}</b> / {thresh} threshold</span>
    </div>
    <div class="score-track">
      <div class="score-fill" style="width:{min(int(score/thresh*100),100)}%;background:{'var(--re)' if is_mal else 'var(--ye)' if score>=thresh//2 else 'var(--gr)'}"></div>
    </div>
  </div>

  <!-- Metadata + Hashes -->
  <div class="grid2">
    <div class="card"><h2>&#128196; File Metadata</h2><table class="dt"><tbody>{meta_rows}</tbody></table></div>
    <div class="card"><h2>&#128273; Cryptographic Hashes</h2><table class="dt"><tbody>{hash_rows}</tbody></table></div>
  </div>

  <!-- Entropy + File Type -->
  <div class="grid2">
    <div class="card"><h2>&#128202; Entropy Analysis</h2><table class="dt"><tbody>{ent_rows}</tbody></table></div>
    <div class="card">
      <h2>&#128269; File Type Detection</h2>
      <h3>TrID</h3><table class="dt"><tbody>{trid_rows}</tbody></table>
      <h3>Detect-It-Easy</h3><table class="dt"><tbody>{die_rows}</tbody></table>
    </div>
  </div>

  <!-- VirusTotal -->
  <div class="card">
    <h2>&#129440; VirusTotal Results</h2>
    <table class="dt"><tbody>{vt_rows}</tbody></table>
    {vt_link}
    {vt_det_html}
  </div>

  <!-- PE Analysis -->
  <div class="card">
    <h2>&#9881; PE File Analysis</h2>
    {'<table class="dt"><tbody>' + pe_basic + '</tbody></table>' + pe_sec_html + pe_imp_html if pe else '<p class="dim pad">Not a PE file or PE analysis was skipped.</p>'}
  </div>

  <!-- YARA -->
  <div class="card">
    <h2>&#127919; YARA Scan Results</h2>
    <div class="pad">{yara_html}</div>
  </div>

  <!-- Suspicious Indicators -->
  <div class="card">
    <h2>&#128300; Suspicious Indicators</h2>
    <h3>Suspicious Windows APIs</h3>
    <div class="pad">{sus_apis_html}</div>
    {'<h3>Suspicious String Patterns</h3>' + sus_str_html if sus.get('suspicious_strings') else ''}
    {'<h3>FLOSS Decoded (Obfuscated) Strings</h3>' + floss_html if strs.get('floss_decoded') else ''}
  </div>

  <!-- Network -->
  <div class="card">
    <h2>&#127760; Network Indicators</h2>
    <h3>IP Addresses</h3><div class="pad">{net_ip_html}</div>
    {'<h3>URLs</h3>' + net_url_html if net.get('urls') else ''}
    {'<h3>Domains</h3><div class="pad">' + net_dom_html + '</div>' if net.get('domains') else ''}
  </div>

  <!-- Classification -->
  <div class="card">
    <h2>&#129516; Malware Classification</h2>
    {'<table class="dt"><thead><tr><th>Type</th><th>Score</th><th>Confidence</th></tr></thead><tbody>' + type_rows + '</tbody></table>' if type_rows else '<p class="dim pad">No malware types identified.</p>'}
    {'<h3>Evidence &amp; Reasons</h3><table class="dt"><thead><tr><th>Type</th><th>Evidence</th></tr></thead><tbody>' + ev_rows + '</tbody></table>' if ev_rows else ''}
  </div>

</div>

<div class="foot">
  Generated by Static Malware Analysis Toolkit v3.0 &nbsp;&middot;&nbsp; {_esc(now)}<br>
  <span style="opacity:.4">This report is for forensic and educational purposes only.</span>
</div>
</body>
</html>"""

    try:
        with open(out_path,"w",encoding="utf-8") as f: f.write(html)
        rok(f"HTML report saved: {out_path}")
    except (IOError, OSError) as e:
        rbad(f"Could not save HTML report: {e}")

# ═════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Static malware analysis toolkit for Windows",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python analyze.py suspicious.exe\n"
            "  python analyze.py malware.dll --output report.json\n"
            "  python analyze.py sample.bin --no-floss --no-vt\n"
        ),
    )
    parser.add_argument("file",               help="Path to the file to analyse")
    parser.add_argument("--output",    "-o",  help="JSON report path (default: <name>_analysis.json)")
    parser.add_argument("--html",             help="HTML report path (default: <name>_report.html)")
    parser.add_argument("--no-floss",         action="store_true", help="Skip FLOSS (faster)")
    parser.add_argument("--no-pe",            action="store_true", help="Skip PE analysis")
    parser.add_argument("--no-yara",          action="store_true", help="Skip YARA scan")
    parser.add_argument("--no-vt",            action="store_true", help="Skip VirusTotal lookup")
    parser.add_argument("--strings-only",     action="store_true", help="Only dump strings and exit")
    parser.add_argument("--show-all-strings", action="store_true", help="Print every extracted string")
    args = parser.parse_args()

    banner()
    start = time.perf_counter()

    if not check_file(args.file): sys.exit(1)

    report = {}
    base   = os.path.splitext(os.path.basename(args.file))[0]

    # 1 – Metadata & Hashes
    rinfo("Collecting file metadata and computing hashes ...")
    meta   = get_file_metadata(args.file)
    hashes = get_hashes(args.file)
    report["metadata"] = {**meta, "hashes": hashes}
    print_metadata(meta, hashes)

    if args.strings_only:
        for s in run_strings(args.file): print(s)
        sys.exit(0)

    # 2 – Entropy
    rinfo("Calculating entropy ...")
    ent = get_entropy(args.file)
    report["entropy"] = ent
    print_entropy(ent)

    # 3 – File type
    rinfo("Running TrID ...")
    trid = run_trid(args.file)
    rinfo("Running Detect-It-Easy ...")
    die  = run_die(args.file)
    report["file_types"] = {"trid":trid,"die":die}
    print_file_types(trid, die)

    # 4 – Strings
    rinfo("Extracting strings ...")
    strings_list = run_strings(args.file)
    floss_data   = {"static":[],"decoded":[],"stack":[]}
    if not args.no_floss:
        rinfo("Running FLOSS (may take a moment) ...")
        floss_data = run_floss(args.file)

    all_strings = list(dict.fromkeys(
        strings_list + floss_data.get("static",[])
        + floss_data.get("decoded",[]) + floss_data.get("stack",[])))
    suspicious = find_suspicious_strings(all_strings)
    net        = extract_network_indicators(all_strings)
    report["strings"]            = {"count":len(all_strings),
                                    "floss_decoded":floss_data.get("decoded",[]),
                                    "floss_stack"  :floss_data.get("stack",[]),
                                    "sample"       :all_strings[:200]}
    report["suspicious_strings"] = suspicious
    report["network_indicators"] = net
    print_strings_summary(all_strings, floss_data, suspicious, net)

    if args.show_all_strings:
        section_header("ALL EXTRACTED STRINGS")
        for s in all_strings: rprint(f"  {s}")

    # 5 – PE
    pe_data = None
    if not args.no_pe:
        rinfo("Analysing PE structure ...")
        pe_data = analyze_pe(args.file)
        report["pe_analysis"] = pe_data
        print_pe_info(pe_data)

    # 6 – YARA
    yara_matches = []
    if not args.no_yara:
        rinfo("Running embedded YARA rules ...")
        yara_matches = run_yara(args.file)
        report["yara_matches"] = yara_matches
        print_yara_results(yara_matches)

    # 7 – VirusTotal
    vt_result = {"status":"skipped","message":"VirusTotal lookup was skipped."}
    if not args.no_vt:
        vt_result = virustotal_lookup(hashes.get("SHA256",""), args.file)
    report["virustotal"] = vt_result
    print_vt_results(vt_result)

    # 8 – Classify
    rinfo("Classifying ...")
    classification = classify_malware(yara_matches, suspicious, ent, pe_data, net)
    report["classification"] = classification
    print_verdict(classification)

    elapsed = time.perf_counter() - start
    if HAS_RICH: console.print(f"\n  [bold cyan]Analysis completed in {elapsed:.2f}s[/bold cyan]\n")
    else: print(f"\n  Analysis completed in {elapsed:.2f}s\n")

    # Save JSON
    json_path = args.output or (base + "_analysis.json")
    try:
        with open(json_path,"w",encoding="utf-8") as f: json.dump(report,f,indent=2,default=str)
        rok(f"JSON report saved: {json_path}")
    except (IOError, OSError) as e: rbad(f"Could not save JSON: {e}")

    # Save HTML
    html_path = args.html or (base + "_report.html")
    rinfo("Generating HTML report ...")
    generate_html_report(report, html_path)


if __name__ == "__main__":
    main()
