#!/usr/bin/env python3
"""
DARKTRACE — Advanced Reconnaissance & Intelligence Framework
Terminal Edition for Kali Linux / Security Environments
For authorized security testing and educational purposes only.

Usage:
    python darktrace_lite.py web <domain>          # Web reconnaissance
    python darktrace_lite.py file <filepath>        # File intelligence
    python darktrace_lite.py full <domain>          # Full scan (web + deep)

Requirements: Python 3.8+  (no pip install needed — uses stdlib only)
Optional:     pip install requests   (for HTTP checks — pre-installed on Kali)

Author:  DARKTRACE Project
License: Educational use only
"""

import argparse
import json
import os
import re
import socket
import ssl
import struct
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# ─── Force UTF-8 on Windows ─────────────────────────────────────────────────
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# ─── Try importing requests (optional — fallback to urllib) ──────────────────
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    import urllib.request
    import urllib.error
    HAS_REQUESTS = False


# ═══════════════════════════════════════════════════════════════════════════════
#  ANSI TERMINAL COLORS (works on Kali/Linux terminals natively)
# ═══════════════════════════════════════════════════════════════════════════════

class C:
    """ANSI color codes for terminal output."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"

    @staticmethod
    def sev(level: str) -> str:
        colors = {"CRITICAL": C.RED, "HIGH": C.YELLOW, "MEDIUM": C.MAGENTA, "LOW": C.GREEN, "INFO": C.DIM}
        return colors.get(level, C.WHITE)


def banner():
    print(f"""
  {C.CYAN}{C.BOLD}██████   █████  ██████  ██   ██ ████████ ██████   █████  ██████ ███████
  ██   ██ ██   ██ ██   ██ ██  ██     ██    ██   ██ ██   ██ ██    ██ 
  ██   ██ ███████ ██████  █████      ██    ██████  ███████ ██    █████
  ██   ██ ██   ██ ██   ██ ██  ██     ██    ██   ██ ██   ██ ██    ██
  ██████  ██   ██ ██   ██ ██   ██    ██    ██   ██ ██   ██ ██████ ███████{C.RESET}

  {C.MAGENTA}Advanced Universal Reconnaissance & Intelligence Framework{C.RESET}
  {C.DIM}v1.0.0{C.RESET}

  {C.YELLOW}[!] For authorized security testing & educational purposes only{C.RESET}
""")


def section(title: str):
    width = 70
    print(f"\n{C.CYAN}{C.BOLD}{'─' * width}")
    print(f"  {title}")
    print(f"{'─' * width}{C.RESET}")


def finding(severity: str, ftype: str, desc: str):
    color = C.sev(severity)
    sev_display = f"{color}{C.BOLD}[{severity:8}]{C.RESET}"
    type_display = f"{C.CYAN}{ftype:22}{C.RESET}"
    print(f"  {sev_display} {type_display} {desc}")


def status(msg: str, icon: str = "*"):
    print(f"  {C.BLUE}[{icon}]{C.RESET} {msg}")


def success(msg: str):
    print(f"  {C.GREEN}[+]{C.RESET} {msg}")


def warning(msg: str):
    print(f"  {C.YELLOW}[!]{C.RESET} {msg}")


def error(msg: str):
    print(f"  {C.RED}[-]{C.RESET} {msg}")


# ═══════════════════════════════════════════════════════════════════════════════
#  FINDINGS STORAGE
# ═══════════════════════════════════════════════════════════════════════════════

class ScanResults:
    """Collects all findings during a scan."""

    def __init__(self, target: str, scan_type: str):
        self.target = target
        self.scan_type = scan_type
        self.findings: List[Dict] = []
        self.start_time = datetime.now()

    def add(self, severity: str, ftype: str, description: str, detail: str = ""):
        self.findings.append({
            "severity": severity,
            "type": ftype,
            "description": description,
            "detail": detail,
            "timestamp": datetime.now().isoformat(),
        })
        finding(severity, ftype, description)

    @property
    def risk_score(self) -> int:
        weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 1}
        score = sum(weights.get(f["severity"], 0) for f in self.findings)
        return min(score, 100)

    @property
    def severity_counts(self) -> Dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        return counts

    def print_summary(self):
        elapsed = (datetime.now() - self.start_time).total_seconds()
        score = self.risk_score
        counts = self.severity_counts

        if score >= 80:
            risk_label, risk_color = "CRITICAL RISK", C.RED
        elif score >= 50:
            risk_label, risk_color = "HIGH RISK", C.YELLOW
        elif score >= 20:
            risk_label, risk_color = "MEDIUM RISK", C.MAGENTA
        else:
            risk_label, risk_color = "LOW RISK", C.GREEN

        print(f"""
{C.CYAN}{C.BOLD}══════════════════════════════════════════════════════════════════════{C.RESET}
                        SCAN RESULTS SUMMARY
{C.CYAN}{C.BOLD}══════════════════════════════════════════════════════════════════════{C.RESET}
  {C.BOLD}Target:{C.RESET}        {self.target}
  {C.BOLD}Scan Type:{C.RESET}     {self.scan_type.upper()}
  {C.BOLD}Duration:{C.RESET}      {elapsed:.1f} seconds
  {C.BOLD}Total Findings:{C.RESET} {len(self.findings)}

  {C.BOLD}Risk Score:{C.RESET}    {risk_color}{C.BOLD}{score}/100 — {risk_label}{C.RESET}

  {C.BOLD}Severity Breakdown:{C.RESET}
    {C.RED}CRITICAL: {counts['CRITICAL']:3}{C.RESET}  |  {C.YELLOW}HIGH: {counts['HIGH']:3}{C.RESET}  |  {C.MAGENTA}MEDIUM: {counts['MEDIUM']:3}{C.RESET}  |  {C.GREEN}LOW: {counts['LOW']:3}{C.RESET}  |  {C.DIM}INFO: {counts['INFO']:3}{C.RESET}
{C.CYAN}{C.BOLD}══════════════════════════════════════════════════════════════════════{C.RESET}""")

# ═══════════════════════════════════════════════════════════════════════════════
#  WEB RECONNAISSANCE MODULE
# ═══════════════════════════════════════════════════════════════════════════════

# Common ports to scan
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt2",
    9200: "Elasticsearch", 27017: "MongoDB",
}

# Security headers to check
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]

# Tech fingerprints
TECH_FINGERPRINTS = {
    "WordPress": ["wp-content", "wp-includes", "wp-json"],
    "Drupal": ["drupal", "sites/default"],
    "Joomla": ["joomla", "/administrator/"],
    "Django": ["csrfmiddlewaretoken", "django"],
    "Laravel": ["laravel_session", "laravel"],
    "React": ["react", "_next", "react-root", "__NEXT_DATA__"],
    "Angular": ["ng-version", "ng-app", "angular"],
    "Vue.js": ["vue", "__vue__"],
    "jQuery": ["jquery"],
    "Bootstrap": ["bootstrap"],
    "Nginx": ["nginx"],
    "Apache": ["apache"],
    "Express": ["express", "X-Powered-By: Express"],
    "PHP": ["X-Powered-By: PHP", ".php"],
    "ASP.NET": ["X-AspNet", "__VIEWSTATE", "asp.net"],
    "Cloudflare": ["cloudflare", "cf-ray"],
}

# Admin panel paths
ADMIN_PATHS = [
    "/admin", "/admin/login", "/administrator", "/wp-admin", "/wp-login.php",
    "/login", "/dashboard", "/panel", "/cpanel", "/phpmyadmin",
    "/manager", "/console", "/portal", "/backend",
]

# Sensitive paths
SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/.git/HEAD", "/.htaccess", "/.htpasswd",
    "/robots.txt", "/sitemap.xml", "/phpinfo.php", "/info.php",
    "/backup", "/backup.zip", "/backup.sql", "/db_backup",
    "/config.php", "/config.yaml", "/config.json", "/wp-config.php",
    "/swagger.json", "/api-docs", "/swagger-ui.html", "/openapi.json",
    "/server-status", "/server-info", "/.DS_Store",
    "/composer.json", "/package.json", "/requirements.txt",
    "/web.config", "/crossdomain.xml", "/security.txt",
    "/.well-known/security.txt",
]

# Common subdomains
SUBDOMAINS = [
    "www", "mail", "ftp", "api", "admin", "dev", "staging", "test",
    "blog", "shop", "cdn", "static", "media", "portal", "vpn",
    "remote", "webmail", "dashboard", "panel", "login", "auth",
    "beta", "demo", "docs", "help", "support", "status",
    "git", "jenkins", "ci", "monitor", "grafana", "kibana",
    "redis", "db", "mysql", "postgres", "elastic", "search",
    "intranet", "internal", "backup", "old", "new", "app",
    "m", "mobile", "secure", "gateway", "proxy", "ns1", "ns2",
]


def resolve_ip(domain: str) -> Optional[str]:
    """Resolve domain to IP address."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def scan_port(host: str, port: int, timeout: float = 2.0) -> bool:
    """Check if a port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def grab_banner(host: str, port: int, timeout: float = 2.0) -> str:
    """Attempt to grab service banner."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()
        return banner[:100] if banner else ""
    except Exception:
        return ""


def http_get(url: str, timeout: int = 8) -> Tuple[int, Dict, str]:
    """HTTP GET request — returns (status_code, headers, body)."""
    if HAS_REQUESTS:
        try:
            r = requests.get(url, timeout=timeout, verify=False,
                             allow_redirects=True,
                             headers={"User-Agent": "DARKTRACE/1.0"})
            return r.status_code, dict(r.headers), r.text[:50000]
        except Exception:
            return 0, {}, ""
    else:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "DARKTRACE/1.0"})
            resp = urllib.request.urlopen(req, timeout=timeout)
            headers = dict(resp.headers)
            body = resp.read(50000).decode("utf-8", errors="ignore")
            return resp.status, headers, body
        except Exception:
            return 0, {}, ""


def check_http_path(base_url: str, path: str, timeout: int = 5) -> Tuple[str, int]:
    """Check if a path exists on the target."""
    url = f"{base_url.rstrip('/')}{path}"
    if HAS_REQUESTS:
        try:
            r = requests.get(url, timeout=timeout, verify=False,
                             allow_redirects=False,
                             headers={"User-Agent": "DARKTRACE/1.0"})
            return path, r.status_code
        except Exception:
            return path, 0
    else:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "DARKTRACE/1.0"})
            resp = urllib.request.urlopen(req, timeout=timeout)
            return path, resp.status
        except urllib.error.HTTPError as e:
            return path, e.code
        except Exception:
            return path, 0


# Suppress insecure request warnings
if HAS_REQUESTS:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def web_recon(target: str, results: ScanResults):
    """Full web reconnaissance scan."""

    # Normalize target
    domain = target.replace("http://", "").replace("https://", "").split("/")[0]

    # ── DNS Resolution ────────────────────────────────────────────────────
    section(f"DNS RESOLUTION — {domain}")
    ip = resolve_ip(domain)
    if ip:
        success(f"Resolved: {domain} -> {C.CYAN}{ip}{C.RESET}")
        results.add("INFO", "DNS Resolution", f"Domain resolves to {ip}")
    else:
        error(f"Could not resolve {domain}")
        return

    # ── Port Scanning ─────────────────────────────────────────────────────
    section("PORT SCANNING (Top 20 ports)")
    open_ports = []
    status(f"Scanning {len(COMMON_PORTS)} ports on {ip}...")

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(scan_port, ip, port): (port, svc)
                   for port, svc in COMMON_PORTS.items()}
        for future in as_completed(futures):
            port, service = futures[future]
            if future.result():
                open_ports.append((port, service))
                banner = grab_banner(ip, port)
                banner_info = f" — Banner: {banner[:60]}" if banner else ""

                severity = "CRITICAL" if port in [3389, 5900, 23] else \
                           "CRITICAL" if port in [6379, 27017, 9200] else \
                           "HIGH" if port in [21, 445, 3306, 5432] else \
                           "MEDIUM" if port in [25, 110, 143] else "INFO"

                results.add(severity, "Open Port",
                            f"Port {port}/{service} is open{banner_info}",
                            f"port={port}, service={service}")

    if not open_ports:
        status("No commonly scanned ports found open")
    else:
        success(f"Found {len(open_ports)} open port(s)")

    # ── Subdomain Enumeration ─────────────────────────────────────────────
    section("SUBDOMAIN ENUMERATION")
    status(f"Checking {len(SUBDOMAINS)} common subdomains...")
    found_subs = []

    with ThreadPoolExecutor(max_workers=30) as executor:
        def check_sub(sub):
            fqdn = f"{sub}.{domain}"
            sub_ip = resolve_ip(fqdn)
            return (sub, fqdn, sub_ip)

        futures = [executor.submit(check_sub, sub) for sub in SUBDOMAINS]
        for future in as_completed(futures):
            sub, fqdn, sub_ip = future.result()
            if sub_ip and sub_ip != ip:
                found_subs.append((fqdn, sub_ip))
                results.add("INFO", "Subdomain Found",
                            f"{fqdn} -> {sub_ip}")
            elif sub_ip and sub_ip == ip:
                found_subs.append((fqdn, sub_ip))

    success(f"Found {len(found_subs)} subdomain(s)")

    # ── HTTP Analysis ─────────────────────────────────────────────────────
    base_urls = []
    for proto in ["https", "http"]:
        url = f"{proto}://{domain}"
        code, headers, body = http_get(url)
        if code > 0:
            base_urls.append(url)
            break

    if not base_urls:
        warning("No HTTP/HTTPS service responding")
        return

    base_url = base_urls[0]
    code, headers, body = http_get(base_url)

    # ── HTTP Headers Security Check ───────────────────────────────────────
    section("HTTP SECURITY HEADERS")
    missing_headers = []
    for header in SECURITY_HEADERS:
        found = any(h.lower() == header.lower() for h in headers.keys())
        if found:
            val = headers.get(header, headers.get(header.lower(), ""))
            success(f"{C.GREEN}PRESENT{C.RESET}  {header}: {val[:60]}")
        else:
            missing_headers.append(header)
            results.add("MEDIUM", "Missing Header",
                        f"Missing security header: {header}")
            warning(f"{C.RED}MISSING{C.RESET}  {header}")

    if missing_headers:
        results.add("MEDIUM", "Header Summary",
                     f"{len(missing_headers)}/{len(SECURITY_HEADERS)} security headers missing")

    # ── SSL/TLS Check ─────────────────────────────────────────────────────
    section("SSL / TLS ANALYSIS")
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()

            subject = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))
            not_after = cert.get("notAfter", "")

            success(f"Subject:  {subject.get('commonName', 'N/A')}")
            success(f"Issuer:   {issuer.get('organizationName', 'N/A')}")
            success(f"Expires:  {not_after}")
            success(f"Protocol: {s.version()}")

            results.add("INFO", "SSL Certificate",
                        f"Subject={subject.get('commonName')}, Issuer={issuer.get('organizationName')}, Expires={not_after}")

            # Check expiry
            try:
                from email.utils import parsedate_to_datetime
                exp_date = parsedate_to_datetime(not_after)
                days_left = (exp_date - datetime.now(exp_date.tzinfo)).days
                if days_left < 0:
                    results.add("CRITICAL", "SSL Expired",
                                f"Certificate expired {abs(days_left)} days ago!")
                elif days_left < 30:
                    results.add("HIGH", "SSL Expiring",
                                f"Certificate expires in {days_left} days")
            except Exception:
                pass

            # Check TLS version
            ver = s.version()
            if ver in ("TLSv1", "TLSv1.1"):
                results.add("HIGH", "Weak TLS",
                            f"Deprecated TLS version: {ver}")

    except Exception as e:
        warning(f"SSL check failed: {e}")
        results.add("HIGH", "No SSL/TLS",
                     f"Could not establish SSL connection to {domain}")

    # ── Technology Fingerprinting ─────────────────────────────────────────
    section("TECHNOLOGY FINGERPRINTING")
    full_text = body + " ".join(f"{k}: {v}" for k, v in headers.items())
    detected_tech = []

    for tech, signatures in TECH_FINGERPRINTS.items():
        for sig in signatures:
            if sig.lower() in full_text.lower():
                if tech not in detected_tech:
                    detected_tech.append(tech)
                    results.add("INFO", "Technology",
                                f"Detected: {tech} (signature: {sig})")
                break

    if detected_tech:
        success(f"Detected technologies: {', '.join(detected_tech)}")
    else:
        status("No specific technologies fingerprinted")

    # ── Server Header ─────────────────────────────────────────────────────
    server = headers.get("Server", headers.get("server", ""))
    if server:
        results.add("LOW", "Server Header",
                     f"Server header exposes: {server}")
        success(f"Server: {server}")

    powered_by = headers.get("X-Powered-By", headers.get("x-powered-by", ""))
    if powered_by:
        results.add("LOW", "X-Powered-By",
                     f"X-Powered-By header exposes: {powered_by}")

    # ── Admin Panel Discovery ─────────────────────────────────────────────
    section("ADMIN PANEL & SENSITIVE PATH DISCOVERY")
    status(f"Checking {len(ADMIN_PATHS) + len(SENSITIVE_PATHS)} paths...")

    all_paths = ADMIN_PATHS + SENSITIVE_PATHS
    found_paths = []

    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = [executor.submit(check_http_path, base_url, path) for path in all_paths]
        for future in as_completed(futures):
            path, status_code = future.result()
            if status_code in [200, 301, 302, 403]:
                found_paths.append((path, status_code))

                if path in ["/.env", "/.git/config", "/.git/HEAD", "/.htpasswd"]:
                    severity = "CRITICAL"
                elif path in ["/.htaccess", "/backup", "/backup.zip", "/backup.sql",
                              "/db_backup", "/wp-config.php", "/config.php"]:
                    severity = "HIGH"
                elif "admin" in path or "login" in path or "phpmyadmin" in path:
                    severity = "HIGH" if status_code == 200 else "MEDIUM"
                elif status_code == 403:
                    severity = "LOW"
                else:
                    severity = "MEDIUM"

                status_label = {200: "ACCESSIBLE", 301: "REDIRECT", 302: "REDIRECT", 403: "FORBIDDEN"}
                results.add(severity, "Exposed Path",
                            f"{path} [{status_label.get(status_code, status_code)}]")

    success(f"Found {len(found_paths)} accessible path(s)")

    # ── Email Extraction ──────────────────────────────────────────────────
    section("EMAIL & INFO EXTRACTION")
    emails = set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', body))
    for email in emails:
        results.add("LOW", "Email Found", email)

    if emails:
        success(f"Found {len(emails)} email address(es)")
    else:
        status("No emails found in page source")

    # Extract links
    links = set(re.findall(r'href=["\']([^"\']+)["\']', body, re.IGNORECASE))
    external_links = [l for l in links if l.startswith("http") and domain not in l]
    if external_links:
        status(f"Found {len(external_links)} external link(s)")
        for link in list(external_links)[:5]:
            results.add("INFO", "External Link", link[:80])


# ═══════════════════════════════════════════════════════════════════════════════
#  FILE INTELLIGENCE MODULE
# ═══════════════════════════════════════════════════════════════════════════════

# Secret detection patterns
SECRET_PATTERNS = [
    ("AWS Access Key",      r'AKIA[0-9A-Z]{16}',                                "CRITICAL"),
    ("AWS Secret Key",      r'(?i)(aws_secret_access_key|aws_secret)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})', "CRITICAL"),
    ("Private Key",         r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----',      "CRITICAL"),
    ("JWT Token",           r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', "HIGH"),
    ("GitHub Token",        r'ghp_[A-Za-z0-9]{36}',                              "HIGH"),
    ("Slack Token",         r'xox[bprs]-[A-Za-z0-9\-]+',                         "HIGH"),
    ("Stripe Key",          r'sk_live_[0-9a-zA-Z]{24,}',                         "HIGH"),
    ("Google API Key",      r'AIza[0-9A-Za-z\-_]{35}',                           "HIGH"),
    ("Generic API Key",     r'(?i)(api[_-]?key|api[_-]?secret|apikey)\s*[=:]\s*["\']?([A-Za-z0-9\-_]{16,})', "HIGH"),
    ("Bearer Token",        r'(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}',              "HIGH"),
    ("Database URL",        r'(?i)(mysql|postgresql|postgres|mongodb|redis|sqlite):\/\/[^\s<>"]+', "HIGH"),
    ("Hardcoded Password",  r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?[^\s"\']{4,}', "MEDIUM"),
    ("Hardcoded Secret",    r'(?i)(secret|secret_key)\s*[=:]\s*["\']?[^\s"\']{4,}', "MEDIUM"),
    ("Internal IP",         r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b', "MEDIUM"),
    ("Email Address",       r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', "LOW"),
]


def file_intelligence(filepath: str, results: ScanResults):
    """Analyze a file for secrets, metadata, and sensitive content."""
    path = Path(filepath)

    if not path.exists():
        error(f"File not found: {filepath}")
        return

    # ── File Metadata ─────────────────────────────────────────────────────
    section(f"FILE METADATA — {path.name}")

    stat = path.stat()
    size_kb = stat.st_size / 1024
    size_display = f"{size_kb:.1f} KB" if size_kb < 1024 else f"{size_kb/1024:.1f} MB"

    success(f"Filename:  {path.name}")
    success(f"Full path: {path.absolute()}")
    success(f"Size:      {size_display} ({stat.st_size} bytes)")
    success(f"Extension: {path.suffix or 'None'}")
    success(f"Modified:  {datetime.fromtimestamp(stat.st_mtime).isoformat()}")

    results.add("INFO", "File Metadata",
                f"{path.name} — {size_display}, ext={path.suffix}")

    # ── Read File Content ─────────────────────────────────────────────────
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        try:
            with open(filepath, "rb") as f:
                raw = f.read()
            content = raw.decode("ascii", errors="ignore")
        except Exception as e:
            error(f"Cannot read file: {e}")
            return

    # ── Secret Scanning ───────────────────────────────────────────────────
    section("SECRET & SENSITIVE DATA SCAN")
    status(f"Scanning with {len(SECRET_PATTERNS)} pattern rules...")

    total_secrets = 0
    for name, pattern, severity in SECRET_PATTERNS:
        matches = re.findall(pattern, content)
        if matches:
            for match in matches[:3]:  # Limit to 3 per pattern
                if isinstance(match, tuple):
                    match = match[0]
                display = str(match)[:80] + ("..." if len(str(match)) > 80 else "")
                results.add(severity, name, f"Found: {display}")
                total_secrets += 1

    if total_secrets == 0:
        success("No secrets or sensitive patterns detected")
    else:
        warning(f"Found {total_secrets} secret(s) / sensitive patterns")

    # ── String Analysis (for binary files) ────────────────────────────────
    if path.suffix.lower() not in [".txt", ".py", ".js", ".json", ".yaml",
                                    ".yml", ".xml", ".html", ".css", ".md",
                                    ".csv", ".env", ".conf", ".cfg", ".ini",
                                    ".php", ".rb", ".go", ".java", ".c", ".h"]:
        section("BINARY STRING EXTRACTION")
        try:
            with open(filepath, "rb") as f:
                raw = f.read()

            # Extract printable strings (min length 6)
            strings = re.findall(rb'[\x20-\x7e]{6,}', raw)
            status(f"Extracted {len(strings)} printable strings from binary")

            # Check for sensitive keywords in strings
            keywords = ["password", "passwd", "secret", "token", "api_key",
                        "apikey", "private_key", "aws", "bearer", "authorization",
                        "admin", "root", "login"]
            sensitive_strings = []

            for s in strings:
                decoded = s.decode("ascii", errors="ignore").lower()
                for kw in keywords:
                    if kw in decoded:
                        sensitive_strings.append(s.decode("ascii", errors="ignore"))
                        break

            if sensitive_strings:
                results.add("MEDIUM", "Binary Strings",
                            f"Found {len(sensitive_strings)} strings with sensitive keywords")
                for s in sensitive_strings[:5]:
                    results.add("LOW", "Suspicious String", s[:80])

        except Exception as e:
            warning(f"Binary analysis failed: {e}")

    # ── URL Extraction ────────────────────────────────────────────────────
    section("URL & ENDPOINT EXTRACTION")
    urls = set(re.findall(r'https?://[^\s<>"\']+', content))
    if urls:
        for url in list(urls)[:10]:
            results.add("INFO", "Embedded URL", url[:80])
        success(f"Found {len(urls)} embedded URL(s)")
    else:
        status("No URLs found in file content")

    # ── PDF Metadata (if PDF) ─────────────────────────────────────────────
    if path.suffix.lower() == ".pdf":
        section("PDF METADATA EXTRACTION")
        try:
            with open(filepath, "rb") as f:
                raw = f.read()
            # Basic PDF metadata extraction (no deps needed)
            author = re.search(rb'/Author\s*\(([^)]+)\)', raw)
            creator = re.search(rb'/Creator\s*\(([^)]+)\)', raw)
            producer = re.search(rb'/Producer\s*\(([^)]+)\)', raw)
            title = re.search(rb'/Title\s*\(([^)]+)\)', raw)

            if author:
                val = author.group(1).decode("utf-8", errors="ignore")
                results.add("LOW", "PDF Author", f"Author: {val}")
                success(f"Author:   {val}")
            if creator:
                val = creator.group(1).decode("utf-8", errors="ignore")
                results.add("INFO", "PDF Creator", f"Creator: {val}")
                success(f"Creator:  {val}")
            if producer:
                val = producer.group(1).decode("utf-8", errors="ignore")
                success(f"Producer: {val}")
            if title:
                val = title.group(1).decode("utf-8", errors="ignore")
                success(f"Title:    {val}")
        except Exception as e:
            warning(f"PDF metadata extraction failed: {e}")

    # ── Image EXIF (if image — basic check without Pillow) ────────────────
    if path.suffix.lower() in [".jpg", ".jpeg"]:
        section("JPEG EXIF EXTRACTION")
        try:
            with open(filepath, "rb") as f:
                raw = f.read()

            # Look for EXIF marker
            if b"Exif" in raw[:100]:
                results.add("INFO", "EXIF Data", "EXIF data present in image")
                success("EXIF data detected in image")

                # Try to find GPS data
                if b"GPS" in raw:
                    results.add("HIGH", "GPS Location",
                                "GPS coordinates may be embedded in image EXIF data")
                    warning("GPS location data found in image!")

                # Look for device info
                make = re.search(rb'Make\x00([^\x00]{2,30})', raw)
                model = re.search(rb'Model\x00([^\x00]{2,30})', raw)
                if make:
                    val = make.group(1).decode("ascii", errors="ignore")
                    results.add("LOW", "Camera Make", f"Device: {val}")
                    success(f"Device Make: {val}")
                if model:
                    val = model.group(1).decode("ascii", errors="ignore")
                    results.add("LOW", "Camera Model", f"Model: {val}")
                    success(f"Device Model: {val}")
            else:
                status("No EXIF data found")
        except Exception as e:
            warning(f"EXIF extraction failed: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
#  ATTACK ANALYSIS & RECOMMENDATIONS
# ═══════════════════════════════════════════════════════════════════════════════

def generate_attack_analysis(results: ScanResults):
    """Print attack analysis and recommendations based on findings."""
    section("ATTACK SURFACE ANALYSIS")

    findings = results.findings
    types_found = set(f["type"] for f in findings)
    severities = results.severity_counts

    # Attack scenarios
    attacks = []

    if "AWS Access Key" in types_found or "AWS Secret Key" in types_found:
        attacks.append({
            "title": "AWS Cloud Compromise",
            "risk": "CRITICAL",
            "chain": [
                "Attacker uses leaked AWS credentials to authenticate",
                "Enumerates S3 buckets, EC2 instances, databases",
                "Exfiltrates data from S3 or RDS",
                "Creates backdoor IAM user for persistence",
            ],
            "fix": "Rotate AWS keys immediately. Use IAM least-privilege. Enable GuardDuty.",
            "mitre": "TA0006 (Credential Access) -> T1552 (Unsecured Credentials)",
        })

    if any("admin" in f["description"].lower() or "login" in f["description"].lower()
           for f in findings if f["type"] == "Exposed Path"):
        attacks.append({
            "title": "Admin Panel Brute-Force",
            "risk": "HIGH",
            "chain": [
                "Attacker discovers exposed admin/login panel",
                "Tries default credentials (admin/admin, admin/password)",
                "Runs automated brute-force with Hydra or Burp Suite",
                "Gains admin access -> full application control",
            ],
            "fix": "Restrict admin panel to internal network/VPN. Add MFA and rate limiting.",
            "mitre": "TA0001 (Initial Access) -> T1190 (Exploit Public-Facing App)",
        })

    if "JWT Token" in types_found:
        attacks.append({
            "title": "Session Hijacking via JWT",
            "risk": "HIGH",
            "chain": [
                "Attacker finds JWT token in exposed file",
                "Decodes token to read user ID and role claims",
                "Replays token to impersonate user or admin",
                "If secret is weak, cracks it to forge unlimited tokens",
            ],
            "fix": "Rotate JWT secret. Use short expiry. Store tokens in httpOnly cookies.",
            "mitre": "TA0006 (Credential Access) -> T1552",
        })

    if "Database URL" in types_found:
        attacks.append({
            "title": "Direct Database Access",
            "risk": "CRITICAL",
            "chain": [
                "Attacker extracts DB connection string with credentials",
                "Connects to database directly if port is open",
                "Dumps all tables: users, payments, PII",
                "Creates backdoor DB user for persistence",
            ],
            "fix": "Change DB password. Restrict to localhost only. Use secrets manager.",
            "mitre": "TA0009 (Collection) -> T1074 (Data Staged)",
        })

    if any(f["type"] == "Exposed Path" and ".env" in f["description"] for f in findings):
        attacks.append({
            "title": ".env File Exposure — Full Secret Dump",
            "risk": "CRITICAL",
            "chain": [
                "Attacker requests /.env directly",
                "Reads all environment variables: DB creds, API keys, secrets",
                "Uses credentials to access database and third-party APIs",
                "App secret key allows forging authenticated sessions",
            ],
            "fix": "Remove .env from web root. Add deny rules in server config. Rotate ALL secrets.",
            "mitre": "TA0006 (Credential Access) -> T1552",
        })

    if any(f["type"] == "Exposed Path" and ".git" in f["description"] for f in findings):
        attacks.append({
            "title": "Source Code Exposure via .git",
            "risk": "CRITICAL",
            "chain": [
                "Attacker accesses /.git/config to confirm exposure",
                "Uses git-dumper to reconstruct full repository",
                "Reads source code, finds hardcoded secrets in history",
                "Identifies vulnerabilities (SQLi, auth bypass) from code",
            ],
            "fix": "Block /.git in server config. Assume all secrets compromised. Rotate everything.",
            "mitre": "TA0043 (Recon) -> T1592 (Gather Victim Host Info)",
        })

    if severities.get("MEDIUM", 0) >= 3 and "Missing Header" in types_found:
        attacks.append({
            "title": "Client-Side Attack via Missing Headers",
            "risk": "MEDIUM",
            "chain": [
                "Attacker identifies missing CSP and X-Frame-Options",
                "Crafts XSS payload exploiting missing CSP",
                "Steals session cookies via injected JavaScript",
                "Creates clickjacking page with missing X-Frame-Options",
            ],
            "fix": "Add all security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options.",
            "mitre": "TA0001 (Initial Access) -> T1190",
        })

    if any(f["type"] == "Open Port" and "CRITICAL" in f["severity"] for f in findings):
        attacks.append({
            "title": "Network Service Exploitation",
            "risk": "HIGH",
            "chain": [
                "Attacker finds exposed high-risk service (RDP/Redis/MongoDB)",
                "Attempts default credentials or unauthenticated access",
                "Gains remote shell or data access",
                "Pivots to internal network from compromised host",
            ],
            "fix": "Close unnecessary ports. Place services behind VPN. Enable auth on all services.",
            "mitre": "TA0001 (Initial Access) -> T1190",
        })

    if "Private Key" in types_found:
        attacks.append({
            "title": "Private Key Compromise",
            "risk": "CRITICAL",
            "chain": [
                "Attacker finds exposed private key (SSH/TLS)",
                "Uses key to SSH into servers without password",
                "Escalates privileges, accesses all data",
                "If TLS key: performs MITM on encrypted traffic",
            ],
            "fix": "Revoke key immediately. Generate new key pair. Audit all trusting systems.",
            "mitre": "TA0006 (Credential Access) -> T1552",
        })

    if not attacks:
        success("No critical attack scenarios identified")
        return

    for i, atk in enumerate(attacks, 1):
        color = C.sev(atk["risk"])
        print(f"""
  {C.BOLD}{color}┌── ATTACK SCENARIO #{i}: {atk['title']} ──{C.RESET}
  {C.BOLD}{color}│  RISK: {atk['risk']}{C.RESET}
  {C.BOLD}{color}│  MITRE: {atk['mitre']}{C.RESET}
  {color}│{C.RESET}
  {color}│{C.RESET}  {C.BOLD}Attack Chain:{C.RESET}""")
        for step in atk["chain"]:
            print(f"  {color}│{C.RESET}    {C.CYAN}→{C.RESET} {step}")
        print(f"""  {color}│{C.RESET}
  {color}│{C.RESET}  {C.BOLD}Remediation:{C.RESET}
  {color}│{C.RESET}    {C.GREEN}✓{C.RESET} {atk['fix']}
  {color}└{'─' * 60}{C.RESET}""")

    # Overall recommendations
    section("PRIORITIZED RECOMMENDATIONS")

    if severities["CRITICAL"] > 0:
        print(f"  {C.RED}{C.BOLD}[CRITICAL]{C.RESET} Initiate incident response — rotate all leaked credentials immediately")
    if severities["HIGH"] > 0:
        print(f"  {C.YELLOW}{C.BOLD}[HIGH]    {C.RESET} Restrict exposed admin panels and high-risk services behind VPN")
    if severities["MEDIUM"] > 0:
        print(f"  {C.MAGENTA}{C.BOLD}[MEDIUM]  {C.RESET} Implement all missing security headers and harden configuration")
    if severities["LOW"] > 0:
        print(f"  {C.GREEN}{C.BOLD}[LOW]     {C.RESET} Remove information disclosure (server headers, email addresses)")

    print(f"\n  {C.BOLD}Tools for Further Testing:{C.RESET}")
    print(f"    {C.CYAN}•{C.RESET} nmap / masscan — deep port scanning")
    print(f"    {C.CYAN}•{C.RESET} nikto / nuclei — vulnerability scanning")
    print(f"    {C.CYAN}•{C.RESET} Burp Suite — web app testing")
    print(f"    {C.CYAN}•{C.RESET} truffleHog / gitleaks — secret detection")
    print(f"    {C.CYAN}•{C.RESET} sqlmap — SQL injection testing")


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="DARKTRACE — Advanced Reconnaissance & Intelligence Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python darktrace_lite.py web example.com
  python darktrace_lite.py file /path/to/config.txt
  python darktrace_lite.py file document.pdf
  python darktrace_lite.py full example.com

[!] For authorized security testing and educational purposes ONLY.
        """,
    )

    parser.add_argument("mode", choices=["web", "file", "full"],
                        help="Scan mode: web (domain recon), file (file analysis), full (web + deep)")
    parser.add_argument("target", help="Target domain or file path")

    parser.add_argument("-q", "--quiet", action="store_true", help="Skip banner")

    args = parser.parse_args()

    if not args.quiet:
        banner()

    results = ScanResults(args.target, args.mode)

    if args.mode == "web":
        web_recon(args.target, results)
        generate_attack_analysis(results)

    elif args.mode == "file":
        file_intelligence(args.target, results)
        generate_attack_analysis(results)

    elif args.mode == "full":
        # If it looks like a domain, do web scan
        if not os.path.exists(args.target):
            web_recon(args.target, results)
        else:
            file_intelligence(args.target, results)
        generate_attack_analysis(results)

    # Print summary
    results.print_summary()

    print(f"\n  {C.DIM}Scan complete. Stay ethical. 🔒{C.RESET}\n")


if __name__ == "__main__":
    main()
