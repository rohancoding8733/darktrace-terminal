# DARKTRACE
## Advanced Universal Reconnaissance & Intelligence Framework

> For authorized security testing and educational purposes only.

---

## Quick Start

```bash
# No installation needed — just run it
python3 darktrace_lite.py web example.com         # Scan a website
python3 darktrace_lite.py file config.txt         # Scan a file
python3 darktrace_lite.py full example.com        # Full analysis
```

---

## Requirements

- **Python 3.8+** (pre-installed on Kali Linux)
- **No pip install needed** — uses only Python standard library
- Optional: `requests` (pre-installed on Kali) for better HTTP handling

---

## Features

| Feature | Description |
|---------|-------------|
| **Port Scanning** | Scans top 20 ports (SSH, HTTP, RDP, MySQL, etc.) |
| **Subdomain Enumeration** | Checks 50+ common subdomains |
| **SSL/TLS Analysis** | Certificate info, expiry check, protocol version |
| **HTTP Header Check** | Checks 7 security headers |
| **Admin Panel Discovery** | Checks 14 admin paths |
| **Sensitive Path Discovery** | Checks 30+ sensitive files (.env, .git, backup) |
| **Technology Fingerprinting** | Detects 16+ technologies |
| **Secret Scanning** | 15 regex patterns (AWS keys, JWT, passwords, etc.) |
| **PDF Metadata** | Extracts author, creator from PDFs |
| **JPEG EXIF** | Detects GPS data and camera info |
| **MITRE ATT&CK Mapping** | Attack chains with technique references |

---

## Usage Examples

```bash
# Web recon
python3 darktrace_lite.py web scanme.nmap.org
python3 darktrace_lite.py web testphp.vulnweb.com

# File analysis
python3 darktrace_lite.py file /etc/passwd
python3 darktrace_lite.py file suspicious_config.txt
python3 darktrace_lite.py file document.pdf

# Skip banner
python3 darktrace_lite.py web example.com -q
```

---

## Output

- Colored terminal output with severity levels
- Risk score (0-100) with severity breakdown
- Attack chain analysis with MITRE ATT&CK references

---

*DARKTRACE v1.0.0 — Advanced Universal Reconnaissance & Intelligence Framework*
