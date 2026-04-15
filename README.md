<div align="center">

# 🕶 DARKTRACE

### Advanced Universal Reconnaissance & Intelligence Framework
**Terminal Edition**

[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/Platform-Kali%20%7C%20Linux%20%7C%20Windows-lightgrey.svg)]()
[![Dependencies](https://img.shields.io/badge/Dependencies-Zero-success.svg)]()
[![License](https://img.shields.io/badge/License-Educational-magenta.svg)]()

> A frictionless, single-file reconnaissance and intelligence gathering tool built for ethical hackers, penetration testers, and security researchers.

</div>

---

## 🎯 Overview

DARKTRACE is a highly portable, highly modular reconnaissance tool. Designed to operate completely isolated from heavy environments, this "Terminal Edition" requires **zero external dependencies** and no `pip install`. Simply drop the script into your terminal and start gathering intelligence.

It performs **deep intelligence gathering** on websites, extracts metadata from files, parses configuration secrets, and directly maps findings to **MITRE ATT&CK** scenarios for actionable remediation.

---

## ⚡ Quick Start

```shell
# Clone or download the script
git clone https://github.com/rohancoding8733/darktrace-terminal.git
cd darktrace-terminal

# Scan a Website (Web Recon)
python3 darktrace_lite.py web example.com

# Scan a File (File Intelligence)
python3 darktrace_lite.py file config.txt

# Run a Full Scan
python3 darktrace_lite.py full example.com
```

---

## 💎 Key Features

#### 🌐 Web Reconnaissance
*   **Rapid Port Scanning:** Checks the top 20 most critical networking ports for live services.
*   **Subdomain Enumeration:** Actively probes for over 50 hidden administrative or development subdomains.
*   **Technology Fingerprinting:** Detects backend frameworks, load balancers, and CMS systems (WordPress, React, Cloudflare, Nginx, etc.).
*   **Security Header & SSL Analysis:** Evaluates HSTS, CSP, X-Frame-Options, SSL expiry dates, and weak TLS configurations.
*   **Path Discovery:** Silently looks for exposed `.env` files, `/admin` pages, and `.git` configuration exposures.

#### 📂 File & Data Intelligence
*   **Deep Secret Scanning:** Utilizes 15+ regex patterns to detect leaked AWS Keys, JWT Tokens, GitHub PATs, Stripe/Google API Keys, and hardcoded database URLs.
*   **PDF Metadata:** Extracts Author, Creator, and embedded tracking data from `.pdf` documents.
*   **JPEG EXIF Extraction:** Pulls underlying GPS coordinates and camera configurations directly out of raw image bitstreams.

#### 🧠 Attack Mapping Engine
*   **Contextual Scenarios:** Auto-generates attack chains based on discovered misconfigurations.
*   **MITRE ATT&CK Indexing:** Links discovered vulnerabilities directly to standard MITRE techniques (e.g. `TA0006`, `T1552`).
*   **Prioritized Remediation:** Delivers step-by-step mitigation instructions sorted by Critical, High, Medium, and Low severities.

---

## 💻 Usage & Flags

DARKTRACE uses an intuitive CLI syntax.

```text
usage: darktrace_lite.py [-h] [-q] {web,file,full} target

positional arguments:
  {web,file,full}  Scan mode: web (domain recon), file (file analysis), full
  target           Target domain or file path

options:
  -h, --help       show this help message and exit
  -q, --quiet      Skip the UI banner for clean automation
```

#### Example Scans
```shell
# Target a specific bug bounty scope
python3 darktrace_lite.py web target.company.com

# Scan an extracted zip archive file or config
python3 darktrace_lite.py file backup_db.yml

# Check a PDF for hidden tracking metadata 
python3 darktrace_lite.py file confidential_report.pdf
```

---

## 🛠️ Architecture

*   **Self-Contained:** The entire intelligence framework is compressed into a single Python file (`darktrace_lite.py`), making it perfect for rapid deployment on engagements.
*   **Cross-Platform UI:** Advanced terminal rendering using raw ANSI codes guarantees beautiful, structured readouts on Kali Linux, standard Ubuntu, macOS, and modern Windows terminals.
*   **No Third-Party Bloat:** It defaults back to `urllib` natively for requests if optional packages like `requests` are missing.

---

## ⚖️ Legal Disclaimer

> ⚠️ **IMPORTANT:** This tool is intended for explicitly authorized security testing and educational purposes only. 

Unauthorized use against networks or applications you do not own—or do not have explicit, written permission to test—is highly unethical and potentially illegal. The developer assumes no liability and is not responsible for any misuse, damage, or breaches caused by this tool. By using DARKTRACE, you agree to operate equitably and within the bounds of your local laws.
