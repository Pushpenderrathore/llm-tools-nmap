#!/usr/bin/env python3
"""
Ollama + Nmap agent (production-hardened v11).

Changes from v10:
 - FIX I1 (v11): TLS probe runs even when a banner exists but looks HTTP —
                 prevents false-negative on non-standard TLS ports (e.g. 10443)
                 that respond with an HTTP banner before the TLS handshake.
 - FIX I2 (v11): Fingerprint cache TTL — entries expire after CACHE_TTL_HOURS
                 (default 24 h). Stale entries are evicted on load; service
                 changes on rescanned hosts are detected correctly.
 - FIX I3 (v11): Concurrent banner grabbing + fingerprinting via
                 ThreadPoolExecutor — wall-clock time for multi-port hosts
                 drops from O(n) serial to O(1) parallel.
 - FIX I4 (v11): OS fingerprint correlation — when nmap -O detects Windows,
                 SMB and RDP risk scores are elevated and their next_steps
                 are prepended with OS-specific context.
 - FIX I5 (v11): Exploit chaining — after enrichment the engine walks all
                 open ports and emits a prioritised chain_of_attack list
                 ordered by risk, describing how an attacker would pivot
                 from the highest-risk service to lower-risk ones.

Changes from v9:
 - FIX H1 (v10): Rule match_type field.
 - FIX H2 (v10): TLS probe for unknown HTTPS ports.
 - FIX H3 (v10): Per-port banner timeout.
 - FIX H4 (v10): Fingerprint cache (cross-session).

Changes from v8:
 - FIX G1 (v9): FINGERPRINT_RULES split for FTP/SMTP.
 - FIX G2 (v9): HTTPS disambiguation.
 - FIX G3 (v9): Protocol-aware banner probes.
 - FIX G4 (v9): Banner used as version fallback.

Changes from v7:
 - FIX F1 (v8): Service fingerprinting engine.
 - FIX F2 (v8): Fingerprint confidence field.
 - FIX F3 (v8): Banner-grab condition fixed.
 - FIX F4 (v8): Re-enrichment pass after fingerprinting.
 - FIX F5 (v8): FINGERPRINT_RULES expanded.

Changes from v6:
 - FIX T1 (v7): Dynamic scan timeout.
 - FIX T2 (v7): Stage-2 version-scan retry with --version-light.
 - FIX T3 (v7): Banner grabbing.
 - FIX T4 (v7): Expanded SERVICE_INTEL.
 - FIX T5 (v7): Audit log uses ~/scan_audit.log.

Changes from v5:
 - FIX P1 (v6): _open_ports_only() skips hosts with no open ports.
 - FIX P2 (v6): Duplicate open ports deduplicated.
 - FIX P3 (v6): _load_external_intel() validates each entry.

Changes from v4:
 - FIX B1 (v5): State guard in enrich_results.
 - FIX B2 (v5): Expanded SERVICE_INTEL.
 - FIX B3 (v5): Prompt-level port override.
 - FIX B4 (v5): Exposure summary printed after enrichment.
 - FIX B5 (v5): RISK_ORDER includes "none".

Previous changes (v3/v4):
 - FIX R1–R5, FIX V1–V4.
"""

import argparse
import datetime
import ipaddress
import json
import os
import re
import shlex
import socket
import ssl
import subprocess
import sys
import time
import importlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, Iterable, List, Optional

try:
    import ollama
except Exception:
    print("ERROR: 'ollama' python package not installed.", file=sys.stderr)
    print("Install: pip install ollama", file=sys.stderr)
    raise

# ── Optional llm-tools-nmap integration ──────────────────────────────────────

_llm_tools = None
for _name in ("llm_tools_nmap", "llm-tools-nmap", "llm_tools.nmap", "llm_tools_nmap_py"):
    try:
        _llm_tools = importlib.import_module(_name)
        print(f"[*] Imported llm-tools module: {_name}")
        break
    except Exception:
        _llm_tools = None


# ── Security / scan constants ─────────────────────────────────────────────────

_SAFE_TARGET_RE = re.compile(r'^[a-zA-Z0-9.\-:\[\]]{1,253}$')

ALLOWED_FLAGS: set[str] = {
    "-sS", "-sT", "-sV", "-sU", "-O", "-A",
    "-Pn", "-n",
    "-T1", "-T2", "-T3", "-T4", "-T5",
    "--open", "--version-light",
    "--min-rate",
}

DEFAULT_FLAGS       = "-sS -Pn -T4"
SCAN_TIMEOUT        = 120
MAX_XML_BYTES       = 10 * 1024 * 1024
AUDIT_LOG_PATH      = os.path.expanduser("~/scan_audit.log")
INTEL_FILE          = "intel.json"
FINGERPRINT_CACHE   = "fingerprints.json"

# FIX I2: cache entries older than this are considered stale and evicted.
CACHE_TTL_HOURS     = 24

# FIX I3: max worker threads for concurrent banner+fingerprint work.
BANNER_WORKERS      = 20

UDP_SAFE_PORTS = "53,67,68,69,123,137,138,161,162,500,514,520,1194,1900,4500,5353"

RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4, "none": 5}


def _scan_timeout(target: str) -> int:
    resolved = _resolve_to_ip(target)
    if resolved is None:
        return SCAN_TIMEOUT
    try:
        ip = ipaddress.ip_address(resolved)
        if ip.is_loopback:
            return 300
        if ip.is_private:
            return 180
    except ValueError:
        pass
    return SCAN_TIMEOUT


# ── Scan profiles ─────────────────────────────────────────────────────────────

PROFILES: Dict[str, Dict[str, Any]] = {
    "stealth": {
        "flags":       "-sS -Pn -T2",
        "description": "Low-and-slow SYN scan — minimal footprint.",
    },
    "default": {
        "flags":       "-sS -Pn -T4",
        "description": "Balanced SYN scan — good for LAN targets.",
    },
    "aggressive": {
        "flags":       "-sS -sV -O -Pn -T4",
        "description": "Version + OS detection.",
    },
    "udp": {
        "flags":       "-sU -Pn -T4",
        "description": "UDP service discovery (common ports).",
    },
}


def apply_profile(model_flags: Optional[str], profile: str) -> str:
    base = PROFILES.get(profile, PROFILES["default"])["flags"]
    if not model_flags:
        return base

    profile_timing = next(
        (t for t in base.split() if re.match(r'^-T[0-9]$', t)), None
    )

    try:
        model_tokens = shlex.split(model_flags)
    except ValueError:
        model_tokens = []

    merged = [t for t in model_tokens if not re.match(r'^-T[0-9]$', t)]
    if profile_timing:
        merged.append(profile_timing)

    seen: set[str] = set()
    result: List[str] = []
    for tok in merged:
        if tok not in seen:
            seen.add(tok)
            result.append(tok)

    return " ".join(result) if result else base


# ── Exploit intelligence table ────────────────────────────────────────────────

SERVICE_INTEL: Dict[str, Dict[str, Any]] = {
    "ssh": {
        "risk": "medium",
        "notes": "Remote login service. Frequently targeted for brute-force and weak credentials.",
        "next_steps": [
            "Check for weak / default passwords",
            "Enumerate SSH version for known CVEs",
            "Test key-based auth misconfiguration",
        ],
    },
    "http": {
        "risk": "medium",
        "notes": "Plain HTTP — traffic is unencrypted. Large attack surface.",
        "next_steps": [
            "Directory brute-force (gobuster / ffuf)",
            "Check for XSS, SQLi, IDOR",
            "Fingerprint framework via headers / page content",
        ],
    },
    "https": {
        "risk": "medium",
        "notes": "Encrypted web service. Still vulnerable to app-layer attacks.",
        "next_steps": [
            "Check TLS version and cipher strength (testssl.sh)",
            "Run web vulnerability scanner",
            "Inspect certificate validity and SANs",
        ],
    },
    "http-alt": {
        "risk": "medium",
        "notes": "Alternate HTTP port — often a dev server, proxy, or admin panel.",
        "next_steps": [
            "Identify what application is running",
            "Check for exposed admin interfaces",
            "Directory brute-force (gobuster / ffuf)",
        ],
    },
    "ftp": {
        "risk": "high",
        "notes": "FTP transmits credentials in plaintext and often allows anonymous login.",
        "next_steps": [
            "Test anonymous login",
            "Brute-force credentials",
            "Check for writable directories",
        ],
    },
    "rsftp": {
        "risk": "medium",
        "notes": "Non-standard / alternate FTP service.",
        "next_steps": [
            "Banner-grab to identify actual service",
            "Test anonymous login",
            "Compare behaviour against standard FTP attacks",
        ],
    },
    "smb": {
        "risk": "high",
        "notes": "Windows file-sharing — frequently misconfigured or unpatched.",
        "next_steps": [
            "Enumerate shares (smbclient / CrackMapExec)",
            "Check for null sessions",
            "Test for EternalBlue (MS17-010)",
        ],
    },
    "microsoft-ds": {
        "risk": "high",
        "notes": "SMB over port 445. Same attack surface as smb.",
        "next_steps": [
            "Enumerate shares",
            "Check for null sessions",
            "Test for EternalBlue (MS17-010)",
        ],
    },
    "mysql": {
        "risk": "high",
        "notes": "Database service exposed — high-value target.",
        "next_steps": [
            "Try default/empty credentials (root:)",
            "Enumerate accessible databases",
            "Check for UDF privilege escalation",
        ],
    },
    "postgresql": {
        "risk": "high",
        "notes": "PostgreSQL exposed. Often misconfigured with trust auth.",
        "next_steps": [
            "Test with default user 'postgres' and blank password",
            "Enumerate databases",
            "Check pg_hba.conf trust entries via error messages",
        ],
    },
    "mssql": {
        "risk": "high",
        "notes": "Microsoft SQL Server exposed.",
        "next_steps": [
            "Try sa account with blank password",
            "Enable xp_cmdshell if creds obtained",
            "Check for Metasploit auxiliary modules",
        ],
    },
    "rdp": {
        "risk": "high",
        "notes": "Remote Desktop — high-value target, especially without NLA.",
        "next_steps": [
            "Brute-force credentials",
            "Check for BlueKeep (CVE-2019-0708)",
            "Verify NLA is enforced",
        ],
    },
    "vnc": {
        "risk": "high",
        "notes": "VNC remote desktop — commonly runs with no auth or weak passwords.",
        "next_steps": [
            "Test for unauthenticated access",
            "Brute-force VNC password",
            "Check for CVE-2006-2369 (RealVNC auth bypass)",
        ],
    },
    "telnet": {
        "risk": "critical",
        "notes": "Cleartext protocol — credentials visible on the wire.",
        "next_steps": [
            "Capture credentials via MITM",
            "Try default credentials",
            "Recommend immediate replacement with SSH",
        ],
    },
    "smtp": {
        "risk": "medium",
        "notes": "Mail transfer agent. Can be abused for relay or user enumeration.",
        "next_steps": [
            "Test open relay (RCPT TO external address)",
            "Enumerate users via VRFY / EXPN",
            "Check for outdated software CVEs",
        ],
    },
    "submission": {
        "risk": "medium",
        "notes": "SMTP submission port (587). Should require authentication.",
        "next_steps": [
            "Test unauthenticated relay",
            "Check for STARTTLS enforcement",
            "Enumerate SASL auth mechanisms",
        ],
    },
    "imap": {
        "risk": "medium",
        "notes": "IMAP mail access. Credentials sent in plaintext unless STARTTLS enforced.",
        "next_steps": [
            "Test for cleartext auth (STARTTLS not required)",
            "Brute-force credentials",
            "Check for known Dovecot / Cyrus CVEs",
        ],
    },
    "imaps": {
        "risk": "medium",
        "notes": "IMAP over TLS.",
        "next_steps": [
            "Brute-force credentials",
            "Inspect TLS certificate for info leakage",
            "Check for known mail-server CVEs",
        ],
    },
    "pop3": {
        "risk": "medium",
        "notes": "POP3 mail retrieval. Often cleartext.",
        "next_steps": [
            "Check if STARTTLS is available and enforced",
            "Brute-force credentials",
            "Recommend migration to IMAP+TLS",
        ],
    },
    "pop3s": {
        "risk": "medium",
        "notes": "POP3 over TLS.",
        "next_steps": [
            "Brute-force credentials",
            "Inspect TLS certificate for info leakage",
        ],
    },
    "dns": {
        "risk": "medium",
        "notes": "DNS service. Misconfigured resolvers can be abused for amplification.",
        "next_steps": [
            "Test zone transfer (dig axfr)",
            "Check for open recursion",
            "Enumerate subdomains",
        ],
    },
    "snmp": {
        "risk": "high",
        "notes": "SNMP with default community strings leaks host info.",
        "next_steps": [
            "Try community strings 'public' and 'private'",
            "Enumerate system info (OID walk)",
            "Upgrade to SNMPv3 with auth",
        ],
    },
    "ldap": {
        "risk": "medium",
        "notes": "Directory service — anonymous binds may expose user data.",
        "next_steps": [
            "Test anonymous LDAP bind",
            "Enumerate users and groups",
            "Check for cleartext attribute leakage",
        ],
    },
    "nfs": {
        "risk": "high",
        "notes": "NFS shares may be world-readable or world-writable.",
        "next_steps": [
            "List exports: showmount -e target",
            "Mount and inspect accessible shares",
            "Check for no_root_squash misconfiguration",
        ],
    },
    "rsync": {
        "risk": "high",
        "notes": "rsync daemon — unauthenticated modules expose full filesystem paths.",
        "next_steps": [
            "List modules: rsync target::",
            "Download accessible module contents",
            "Check for writable modules (potential RCE via cron)",
        ],
    },
    "mongodb": {
        "risk": "critical",
        "notes": "MongoDB with no auth exposes all data.",
        "next_steps": [
            "Test unauthenticated access",
            "Enumerate databases and collections",
            "Check for internet-facing exposure immediately",
        ],
    },
    "redis": {
        "risk": "critical",
        "notes": "Redis often runs with no authentication.",
        "next_steps": [
            "Test unauthenticated access (redis-cli -h target ping)",
            "Check for CONFIG SET / slaveof abuse",
            "Look for RCE via cron / authorized_keys write",
        ],
    },
    "upnp": {
        "risk": "medium",
        "notes": "UPnP device discovery — can expose internal network topology.",
        "next_steps": [
            "Enumerate devices with upnp-inspector or Miranda",
            "Check for CallStranger (CVE-2020-12695)",
            "Disable if not required",
        ],
    },
    "afs3-fileserver": {
        "risk": "medium",
        "notes": "Andrew File System. Rare outside academic networks.",
        "next_steps": [
            "Confirm service with banner grab (nc target 7000)",
            "Check if AFS client is genuinely running",
            "Enumerate accessible volumes if confirmed",
        ],
    },
    "ftp-proxy": {
        "risk": "medium",
        "notes": "FTP proxy or relay service.",
        "next_steps": [
            "Identify proxy type via banner grab",
            "Test for unauthenticated access to internal targets",
            "Check for SSRF / bounce-scan abuse",
        ],
    },
    "ollama": {
        "risk": "low",
        "notes": "Local Ollama LLM inference server. Typically loopback-only.",
        "next_steps": [
            "Verify it is bound to 127.0.0.1 only (not 0.0.0.0)",
            "Check /api/tags for loaded models",
            "Ensure no sensitive data is in model context",
        ],
    },
    "http-proxy": {
        "risk": "medium",
        "notes": "HTTP proxy — open proxies can be abused for SSRF and traffic forwarding.",
        "next_steps": [
            "Test for open proxy (CONNECT to external host)",
            "Check for SSRF to internal services",
            "Identify proxy software via banner",
        ],
    },
    "socks5": {
        "risk": "high",
        "notes": "SOCKS5 proxy — if unauthenticated, allows full TCP tunnelling.",
        "next_steps": [
            "Test for unauthenticated access",
            "Attempt to pivot to internal services via proxychains",
            "Identify if authentication is enforced",
        ],
    },
    "cassandra": {
        "risk": "high",
        "notes": "Apache Cassandra — default installs have no authentication.",
        "next_steps": [
            "Connect with cqlsh and list keyspaces",
            "Check for default credentials",
            "Enumerate tables for sensitive data",
        ],
    },
    "elasticsearch": {
        "risk": "critical",
        "notes": "Elasticsearch — historically runs with no auth, exposing all data.",
        "next_steps": [
            "Test unauthenticated access: curl http://target:9200/_cat/indices",
            "Enumerate indices for sensitive data",
            "Check for known CVEs (Log4Shell, RCE via Groovy scripts)",
        ],
    },
}


def _load_external_intel() -> None:
    try:
        with open(INTEL_FILE) as fh:
            external = json.load(fh)
        if not isinstance(external, dict):
            print(f"[!] {INTEL_FILE} must be a JSON object — skipping.", file=sys.stderr)
            return
        accepted = 0
        for key, entry in external.items():
            if not isinstance(entry, dict):
                print(f"[!] Intel entry {key!r} is not a dict — skipping.", file=sys.stderr)
                continue
            if "risk" not in entry:
                print(f"[!] Intel entry {key!r} missing 'risk' field — skipping.", file=sys.stderr)
                continue
            if entry["risk"] not in RISK_ORDER:
                print(f"[!] Intel entry {key!r} has invalid risk {entry['risk']!r} — skipping.",
                      file=sys.stderr)
                continue
            SERVICE_INTEL[key] = entry
            accepted += 1
        print(f"[*] Loaded {accepted}/{len(external)} valid intel entries from {INTEL_FILE}")
    except FileNotFoundError:
        pass
    except (json.JSONDecodeError, OSError) as exc:
        print(f"[!] Could not load {INTEL_FILE}: {exc}", file=sys.stderr)


# ── Service fingerprinting engine ─────────────────────────────────────────────

FINGERPRINT_RULES: List[Dict[str, Any]] = [
    {"match": ["ssh-"],             "service": "ssh",           "match_type": "any"},
    {"match": ["smtp"],             "service": "smtp",          "match_type": "any"},
    {"match": ["esmtp"],            "service": "smtp",          "match_type": "any"},
    {"match": ["postfix"],          "service": "smtp",          "match_type": "any"},
    {"match": ["sendmail"],         "service": "smtp",          "match_type": "any"},
    {"match": ["exim"],             "service": "smtp",          "match_type": "any"},
    {"match": ["ftp"],              "service": "ftp",           "match_type": "any"},
    {"match": ["vsftpd"],           "service": "ftp",           "match_type": "any"},
    {"match": ["proftpd"],          "service": "ftp",           "match_type": "any"},
    {"match": ["filezilla server"], "service": "ftp",           "match_type": "any"},
    {"match": ["http/1."],          "service": "http",          "match_type": "any"},
    {"match": ["http/2"],           "service": "http",          "match_type": "any"},
    {"match": ["<html"],            "service": "http",          "match_type": "any"},
    {"match": ["content-type:"],    "service": "http",          "match_type": "any"},
    {"match": ["server:", "http"],  "service": "http",          "match_type": "all"},
    {"match": ["mysql"],            "service": "mysql",         "match_type": "any"},
    {"match": ["mariadb"],          "service": "mysql",         "match_type": "any"},
    {"match": ["redis"],            "service": "redis",         "match_type": "any"},
    {"match": ["+pong"],            "service": "redis",         "match_type": "any"},
    {"match": ["mongodb"],          "service": "mongodb",       "match_type": "any"},
    {"match": ["cluster_name"],     "service": "elasticsearch", "match_type": "any"},
    {"match": ["ollama"],           "service": "ollama",        "match_type": "any"},
    {"match": ["proxy"],            "service": "http-proxy",    "match_type": "any"},
]

_HTTPS_PORTS: frozenset = frozenset({"443", "8443", "4443", "9443"})

PORT_HINTS: Dict[str, str] = {
    "21":    "ftp",
    "22":    "ssh",
    "23":    "telnet",
    "25":    "smtp",
    "53":    "dns",
    "80":    "http",
    "110":   "pop3",
    "143":   "imap",
    "443":   "https",
    "445":   "microsoft-ds",
    "587":   "submission",
    "993":   "imaps",
    "995":   "pop3s",
    "1433":  "mssql",
    "3306":  "mysql",
    "3389":  "rdp",
    "5432":  "postgresql",
    "5900":  "vnc",
    "6379":  "redis",
    "8080":  "http-alt",
    "8443":  "https",
    "9200":  "elasticsearch",
    "11211": "memcached",
    "11434": "ollama",
    "27017": "mongodb",
}


def _attempt_tls_probe(host: str, port_num: str) -> Optional[str]:
    """
    FIX I1 — shared TLS probe logic used by fingerprint_service().
    Attempts an SSL handshake and returns "https" (confidence tag) on success,
    None on failure.  Extracted so it can be called both when banner is absent
    AND when a banner exists but looks like plain HTTP on a non-standard port.
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        with socket.create_connection((host, int(port_num or 0)), timeout=2.0) as raw_sock:
            with ctx.wrap_socket(raw_sock) as tls_sock:
                cert = tls_sock.getpeercert(binary_form=False) or {}
                cn   = (cert.get("subject") or ((("",),),))[0][0][1]
        label = f"TLS handshake OK (CN={cn})" if cn else "TLS handshake OK"
        return label
    except Exception:
        return None


def fingerprint_service(port: Dict[str, Any]) -> Dict[str, Any]:
    """
    Infer service from banner content then port number.

    Priority:
      1. Existing nmap service+version — never overridden.
      2. Banner-based rule matching (FINGERPRINT_RULES).
      3. TLS probe (FIX I1) — now attempted even when a plain-HTTP banner
         exists on a non-standard port, catching mis-identified TLS services.
      4. Port-number heuristic (PORT_HINTS) — weakest.
    """
    current_service = port.get("service")
    current_version = port.get("version")
    port_num        = str(port.get("port", ""))
    host            = port.get("_host", "")

    # Rule 1 — nmap already identified service + version
    if current_service and current_service not in ("unknown", None) and current_version:
        port.setdefault("confidence", "nmap")
        return port

    banner     = (port.get("banner") or "").lower()
    banner_raw = (port.get("banner") or "")

    def _set_service(service: str, confidence: str, fingerprint: str) -> None:
        if service == "http" and port_num in _HTTPS_PORTS:
            service = "https"
        port["service"]     = service
        port["confidence"]  = confidence
        port["fingerprint"] = fingerprint
        if not current_version and banner_raw:
            port["version"] = banner_raw[:80].strip()
        print(f"    [fingerprint] port {port_num} → {service} ({confidence}: {fingerprint})")

    # Rule 2 — banner rule matching
    if banner:
        for rule in FINGERPRINT_RULES:
            mtype = rule.get("match_type", "any")
            if mtype == "all":
                matched = all(sig in banner for sig in rule["match"])
            else:
                matched = any(sig in banner for sig in rule["match"])
            if matched:
                if not current_service or current_service in ("unknown", None):
                    _set_service(
                        service     = rule["service"],
                        confidence  = "banner-match",
                        fingerprint = str(rule["match"]),
                    )
                    # FIX I1: if we matched HTTP on a non-standard (non-HTTPS) port,
                    # still run a TLS probe — the HTTP banner may be a TLS service
                    # that responded to our plain-TCP probe before the handshake.
                    detected_service = port.get("service", "")
                    if detected_service == "http" and port_num not in _HTTPS_PORTS and host:
                        tls_label = _attempt_tls_probe(host, port_num)
                        if tls_label:
                            print(f"    [fingerprint] port {port_num} → upgrading http → "
                                  f"https (TLS confirmed despite HTTP banner)")
                            _set_service(
                                service     = "https",
                                confidence  = "tls-probe",
                                fingerprint = tls_label,
                            )
                    return port

    # Rule 3 — TLS probe when no banner was received or service still unknown
    if not current_service or current_service in ("unknown", None):
        if host:
            tls_label = _attempt_tls_probe(host, port_num)
            if tls_label:
                _set_service(
                    service     = "https",
                    confidence  = "tls-probe",
                    fingerprint = tls_label,
                )
                return port

    # Rule 4 — port-number fallback
    if port_num in PORT_HINTS:
        if not current_service or current_service in ("unknown", None):
            _set_service(
                service     = PORT_HINTS[port_num],
                confidence  = "port-heuristic",
                fingerprint = f"port {port_num}",
            )

    return port


# ── Fingerprint cache (FIX H4 + FIX I2) ──────────────────────────────────────

def _load_fingerprint_cache() -> Dict[str, Any]:
    """
    FIX H4 — load fingerprints.json.
    FIX I2 — evict entries older than CACHE_TTL_HOURS on load so stale
              service mappings (e.g. after a service restart / port change)
              are never applied.
    """
    try:
        with open(FINGERPRINT_CACHE) as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return {}

        cutoff   = time.time() - CACHE_TTL_HOURS * 3600
        evicted  = 0
        fresh    = {}
        for key, entry in data.items():
            ts = entry.get("_ts", 0)
            if ts >= cutoff:
                fresh[key] = entry
            else:
                evicted += 1

        if evicted:
            print(f"[*] Fingerprint cache: evicted {evicted} stale entries "
                  f"(TTL={CACHE_TTL_HOURS}h)")
        return fresh
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_fingerprint_cache(cache: Dict[str, Any]) -> None:
    """FIX H4 + FIX I2 — persist cache; each entry carries a '_ts' timestamp."""
    try:
        with open(FINGERPRINT_CACHE, "w") as fh:
            json.dump(cache, fh, indent=2)
    except OSError as exc:
        print(f"[!] Could not write fingerprint cache: {exc}", file=sys.stderr)


def apply_fingerprinting(scan_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    FIX F1 — fingerprint open ports.
    FIX H4 — cache layer.
    FIX I3 — concurrent execution via ThreadPoolExecutor.
    """
    cache   = _load_fingerprint_cache()
    changed = False

    # Collect all ports needing fingerprinting
    work_items: List[tuple] = []  # (host_ip, port_dict)

    for host in scan_result.get("hosts", []):
        ip = host.get("ip", "")
        for port in host.get("ports", []):
            if port.get("state") != "open":
                continue
            port["_host"] = ip

            cache_key = f"{ip}:{port.get('port')}"

            if cache_key in cache:
                cached = cache[cache_key]
                if not port.get("service") or port["service"] in ("unknown", None):
                    for field in ("service", "confidence", "fingerprint", "version"):
                        if field in cached:
                            port[field] = cached[field]
                    print(f"    [fingerprint] port {port.get('port')} → "
                          f"{port.get('service')} (cache hit)")
                continue

            work_items.append((ip, port))

    # FIX I3: run fingerprinting in parallel
    if work_items:
        print(f"[*] Fingerprinting {len(work_items)} port(s) concurrently "
              f"(workers={BANNER_WORKERS})...")

        def _fp_task(item):
            _ip, _port = item
            fingerprint_service(_port)
            return (_ip, _port)

        with ThreadPoolExecutor(max_workers=BANNER_WORKERS) as ex:
            futures = {ex.submit(_fp_task, item): item for item in work_items}
            for future in as_completed(futures):
                try:
                    _ip, _port = future.result()
                    if _port.get("confidence") and _port["confidence"] != "nmap":
                        ck = f"{_ip}:{_port.get('port')}"
                        entry = {
                            k: _port[k]
                            for k in ("service", "confidence", "fingerprint", "version")
                            if k in _port
                        }
                        # FIX I2: stamp the cache entry with current time
                        entry["_ts"] = time.time()
                        cache[ck] = entry
                        changed = True
                except Exception as exc:
                    print(f"[!] Fingerprint task failed: {exc}", file=sys.stderr)

    if changed:
        _save_fingerprint_cache(cache)
        print(f"[*] Fingerprint cache updated → {FINGERPRINT_CACHE}")

    return scan_result


# ── OS fingerprint correlation (FIX I4) ───────────────────────────────────────

# Services whose risk and next_steps should be escalated on Windows hosts.
_WINDOWS_ESCALATE: Dict[str, Dict[str, Any]] = {
    "smb": {
        "risk": "critical",
        "os_note": "Windows OS confirmed — SMB is a primary attack vector. "
                   "Prioritise EternalBlue and credential attacks.",
        "prepend_steps": ["Confirm SMB signing disabled: crackmapexec smb target --gen-relay-list"],
    },
    "microsoft-ds": {
        "risk": "critical",
        "os_note": "Windows OS confirmed — SMB/445 is highest priority on Windows targets.",
        "prepend_steps": ["Run: crackmapexec smb target", "Test MS17-010 immediately"],
    },
    "rdp": {
        "risk": "critical",
        "os_note": "Windows OS confirmed — RDP is primary remote access path.",
        "prepend_steps": [
            "Check NLA: nmap -p 3389 --script rdp-enum-encryption target",
            "Test BlueKeep: msfconsole → use auxiliary/scanner/rdp/cve_2019_0708_bluekeep",
        ],
    },
}


def apply_os_correlation(scan_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    FIX I4 — read nmap OS detection data per host and escalate risk/next_steps
    for Windows-specific services when a Windows OS is confirmed.

    nmap -O populates <os><osmatch name="Windows ..."> in XML; our parser stores
    this in host["os"] as a plain string (populated by _run_nmap when present).
    If no OS data is available the function is a no-op.
    """
    for host in scan_result.get("hosts", []):
        os_str = (host.get("os") or "").lower()
        if "windows" not in os_str:
            continue

        print(f"[*] OS correlation: Windows detected on {host.get('ip')} — "
              f"escalating SMB/RDP risk.")

        for port in host.get("ports", []):
            if port.get("state") != "open":
                continue
            service = (port.get("service") or "").lower()
            if service in _WINDOWS_ESCALATE:
                escalation = _WINDOWS_ESCALATE[service]
                port["risk"]       = escalation["risk"]
                port["os_note"]    = escalation["os_note"]
                port["next_steps"] = (
                    escalation["prepend_steps"] + port.get("next_steps", [])
                )
                print(f"    [os-correlation] {service} → risk elevated to "
                      f"{escalation['risk']}")

    return scan_result


# ── Exploit chaining (FIX I5) ─────────────────────────────────────────────────

# Maps (service_a, service_b) → pivot description.
# service_a is the foothold; service_b is the escalation target.
_CHAIN_PIVOTS: Dict[tuple, str] = {
    ("ftp",          "ssh"):           "FTP creds often reused → try on SSH",
    ("ftp",          "smb"):           "FTP write access → plant payload for SMB pickup",
    ("http",         "mysql"):         "Web app may expose DB creds in config files",
    ("http",         "postgresql"):    "Web app may expose DB creds in config files",
    ("http",         "redis"):         "SSRF via web app → hit Redis on loopback",
    ("https",        "mysql"):         "Web app may expose DB creds in config files",
    ("https",        "redis"):         "SSRF via web app → hit Redis on loopback",
    ("smtp",         "ssh"):           "SMTP user enumeration reveals valid usernames → SSH brute",
    ("ssh",          "mysql"):         "SSH access → read /etc/mysql or .my.cnf for DB creds",
    ("ssh",          "redis"):         "SSH access → write authorized_keys via Redis CONFIG SET",
    ("mysql",        "ssh"):           "MySQL UDF → OS command execution → SSH persistence",
    ("postgresql",   "ssh"):           "PostgreSQL COPY TO/FROM PROGRAM → OS command execution",
    ("redis",        "ssh"):           "Redis CONFIG SET dir/dbfilename → write authorized_keys",
    ("mongodb",      "ssh"):           "MongoDB data exfil may contain SSH keys or secrets",
    ("elasticsearch","ssh"):           "Elasticsearch Groovy script RCE → shell → SSH persistence",
    ("smb",          "rdp"):           "SMB credential dump → reuse on RDP",
    ("rdp",          "smb"):           "RDP session → access SMB shares directly",
    ("snmp",         "ssh"):           "SNMP OID walk may leak SSH host keys or credentials",
    ("ldap",         "smb"):           "LDAP user enumeration → targeted SMB credential attacks",
    ("ldap",         "rdp"):           "LDAP user enumeration → targeted RDP brute-force",
    ("vnc",          "ssh"):           "VNC screen access → harvest SSH keys from filesystem",
    ("http-proxy",   "redis"):         "Open proxy → SSRF into internal Redis",
    ("http-proxy",   "elasticsearch"): "Open proxy → SSRF into internal Elasticsearch",
    ("socks5",       "mysql"):         "Unauthenticated SOCKS5 → tunnel into internal MySQL",
    ("socks5",       "postgresql"):    "Unauthenticated SOCKS5 → tunnel into internal PostgreSQL",
}


def build_exploit_chain(scan_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    FIX I5 — for each host, construct a prioritised chain_of_attack list.

    The chain describes how an attacker would move from the highest-risk
    open service to subsequent services using known pivot techniques.
    Stored as host["chain_of_attack"] = [{"step": N, "from": svc, "to": svc, "pivot": desc}].
    """
    for host in scan_result.get("hosts", []):
        open_ports = [
            p for p in host.get("ports", []) if p.get("state") == "open"
        ]
        if not open_ports:
            continue

        # Sort by risk so the chain starts at the highest-risk foothold
        sorted_ports = sorted(
            open_ports,
            key=lambda p: (RISK_ORDER.get(p.get("risk", "unknown"), 4),
                           str(p.get("port", "")).zfill(5)),
        )

        services = [
            (p.get("service") or "").lower().strip()
            for p in sorted_ports
            if (p.get("service") or "").strip()
        ]

        chain: List[Dict[str, Any]] = []
        step = 1

        for i, svc_a in enumerate(services):
            for svc_b in services[i + 1:]:
                pivot = _CHAIN_PIVOTS.get((svc_a, svc_b))
                if pivot:
                    chain.append({
                        "step":  step,
                        "from":  svc_a,
                        "to":    svc_b,
                        "pivot": pivot,
                    })
                    step += 1

        if chain:
            host["chain_of_attack"] = chain
            print(f"\n[EXPLOIT CHAIN] {host.get('ip')} — "
                  f"{len(chain)} pivot(s) identified:")
            for link in chain:
                print(f"  Step {link['step']:2d}: {link['from']} → {link['to']}")
                print(f"            {link['pivot']}")
        else:
            print(f"\n[EXPLOIT CHAIN] {host.get('ip')} — "
                  "no known pivot combinations found.")

    return scan_result


# ── Enrichment ────────────────────────────────────────────────────────────────

def enrich_results(scan_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Attach risk/notes/next_steps/cve_hint per port, then sort ports by risk.
    """
    if "hosts" not in scan_result:
        return scan_result

    for host in scan_result["hosts"]:
        for port in host.get("ports", []):

            if port.get("state") != "open":
                port["risk"]       = "none"
                port["notes"]      = (
                    f"Port not accessible (state: {port.get('state', 'unknown')}). "
                    "No exploitation path."
                )
                port["next_steps"] = []
                continue

            service = (port.get("service") or "").lower().strip()
            version = port.get("version")

            intel = SERVICE_INTEL.get(service) if service else None

            if intel:
                port["risk"]       = intel["risk"]
                port["notes"]      = intel["notes"]
                port["next_steps"] = list(intel["next_steps"])
            elif service:
                port["risk"]       = "unknown"
                port["notes"]      = f"Service '{service}' has no built-in intelligence."
                port["next_steps"] = ["Manual investigation recommended"]
            else:
                port["risk"]       = "unknown"
                port["notes"]      = "Service not identified by nmap."
                port["next_steps"] = []

            if version and service:
                port["cve_hint"] = f"Search: {service} {version} exploit CVE"

        host["ports"].sort(
            key=lambda p: (
                RISK_ORDER.get(p.get("risk", "unknown"), 4),
                p.get("port", "0").zfill(5),
            )
        )

    return scan_result


# ── Banner grabbing ───────────────────────────────────────────────────────────

_BANNER_TIMEOUTS: Dict[int, float] = {
    25:    4.0,
    110:   3.5,
    143:   3.5,
    587:   4.0,
    3306:  3.0,
    5432:  3.0,
    6379:  2.5,
    27017: 3.0,
    9200:  3.0,
}

_BANNER_PROBES: Dict[int, bytes] = {
    22:    b"",
    6379:  b"PING\r\n",
    3306:  b"",
    5432:  b"",
    27017: b"",
    9200:  b"GET / HTTP/1.0\r\n\r\n",
}
_HTTP_PROBE = b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n"


def banner_grab(host: str, port: int, timeout: Optional[float] = None) -> Optional[str]:
    effective_timeout = timeout if timeout is not None else _BANNER_TIMEOUTS.get(port, 2.0)
    probe = _BANNER_PROBES.get(port, _HTTP_PROBE)
    try:
        with socket.create_connection((host, port), timeout=effective_timeout) as s:
            if probe:
                s.sendall(probe)
            data = b""
            try:
                data = s.recv(256)
            except OSError:
                pass
            if not data and not probe:
                try:
                    s.sendall(b"\n")
                    data = s.recv(256)
                except OSError:
                    pass
        banner = data.decode("utf-8", errors="replace").strip()
        return banner[:256] if banner else None
    except OSError:
        return None


def _grab_one_port(ip_str: str, port: Dict[str, Any]) -> None:
    """
    FIX I3: single-port banner-grab task, safe to run in a thread pool.
    Mutates the port dict in-place (same object as in the host list).
    """
    port["_host"] = ip_str
    has_service = port.get("service") and port["service"] not in ("unknown", None)
    has_version = bool(port.get("version"))
    if has_service and has_version:
        return
    if port.get("banner"):
        return

    port_num = port.get("port")
    if not port_num:
        return

    print(f"[*] Banner grab: {ip_str}:{port_num}")
    banner = banner_grab(ip_str, int(port_num))
    if banner:
        port["banner"] = banner
        print(f"    → {banner[:80]!r}")
    else:
        print(f"    → no banner")


def banner_grab_scan(scan_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    FIX T3 / FIX I3 — concurrent banner grabbing for loopback / private IPs.
    """
    tasks: List[tuple] = []

    for host in scan_result.get("hosts", []):
        ip_str = host.get("ip", "")
        try:
            ip = ipaddress.ip_address(ip_str)
            if not (ip.is_loopback or ip.is_private):
                continue
        except ValueError:
            continue

        for port in host.get("ports", []):
            if port.get("state") != "open":
                continue
            tasks.append((ip_str, port))

    if tasks:
        print(f"[*] Banner grabbing {len(tasks)} port(s) concurrently "
              f"(workers={BANNER_WORKERS})...")
        with ThreadPoolExecutor(max_workers=BANNER_WORKERS) as ex:
            futures = [ex.submit(_grab_one_port, ip, p) for ip, p in tasks]
            for f in as_completed(futures):
                try:
                    f.result()
                except Exception as exc:
                    print(f"[!] Banner grab task failed: {exc}", file=sys.stderr)

    return scan_result


def _open_ports_only(scan_result: Dict[str, Any]) -> Dict[str, Any]:
    result = dict(scan_result)
    result["hosts"] = []
    for host in scan_result.get("hosts", []):
        h = dict(host)
        h["ports"] = [p for p in host.get("ports", []) if p.get("state") == "open"]
        if h["ports"]:
            result["hosts"].append(h)
    return result


def print_exposure_summary(res: Dict[str, Any]) -> None:
    for host in res.get("hosts", []):
        open_ports = [p for p in host.get("ports", []) if p.get("state") == "open"]
        if not open_ports:
            print(f"\n[EXPOSURE SUMMARY] {host.get('ip')} — no open ports found.")
            continue

        by_risk: Dict[str, List[str]] = {}
        for p in open_ports:
            by_risk.setdefault(p.get("risk", "unknown"), []).append(
                f"{p['port']}/{p.get('service', '?')}"
            )

        print(f"\n[EXPOSURE SUMMARY] {host.get('ip')} — {len(open_ports)} open port(s)")
        for level in ("critical", "high", "medium", "low", "unknown"):
            if level in by_risk:
                ports_str = ", ".join(by_risk[level])
                print(f"  {level.upper():8s}  {ports_str}")


# ── Audit log ─────────────────────────────────────────────────────────────────

def audit_log(target: str, result: Dict[str, Any]) -> None:
    entry = {
        "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
        "target":    target,
        "result":    result,
    }
    try:
        with open(AUDIT_LOG_PATH, "a") as fh:
            fh.write(json.dumps(entry) + "\n")
        print(f"[*] Audit entry written to {AUDIT_LOG_PATH}")
    except OSError as exc:
        print(f"[!] Could not write audit log: {exc}", file=sys.stderr)


# ── Target validation ─────────────────────────────────────────────────────────

def _resolve_to_ip(target: str) -> Optional[str]:
    try:
        results = socket.getaddrinfo(target, None)
        if results:
            return results[0][4][0]
    except socket.gaierror:
        pass
    return None


def _is_remote(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return not ip.is_loopback and not ip.is_private


def target_allowed(target: str, force: bool = False) -> bool:
    if not _SAFE_TARGET_RE.match(target):
        print(f"[!] Target '{target}' failed format validation (possible injection).")
        return False

    if "/" in target:
        print("[!] CIDR ranges are disabled. Specify a single host.")
        return False

    if force:
        return True

    resolved = _resolve_to_ip(target)
    if resolved is None:
        print(f"[!] Could not resolve '{target}' — refusing to scan.")
        return False

    try:
        ip = ipaddress.ip_address(resolved)
        if _is_remote(ip):
            print(
                f"[!] '{target}' resolves to {resolved} which is not loopback/private. "
                "Use --force to allow."
            )
            return False
        return True
    except ValueError:
        print(f"[!] Resolved address '{resolved}' is not a valid IP.")
        return False


# ── Port helpers ──────────────────────────────────────────────────────────────

def normalise_ports(ports: Optional[str]) -> Optional[str]:
    if ports is None:
        return None
    s = ports.strip().lower()
    if s in ("all", "all ports", "*", "0-65535"):
        return "1-65535"
    return ports


def validate_ports(ports: Optional[str]) -> Optional[str]:
    if ports is None:
        return None
    if re.fullmatch(r'[\d,\-]+', ports):
        return ports
    print(f"[!] Invalid port format '{ports}' — defaulting to top 1000 ports.")
    return None


_TOP_N_RE = re.compile(r'\btop[\s\-]?(\d+)\s+ports?\b', re.IGNORECASE)


def extract_prompt_port_override(prompt: str) -> Optional[str]:
    m = _TOP_N_RE.search(prompt)
    if not m:
        return "NONE"

    n = int(m.group(1))
    if n <= 1000:
        override = f"__top_{n}__"
        print(f"[*] Prompt override: 'top {n} ports' detected — "
              f"will use nmap --top-ports {n}.")
        return override

    print(f"[*] Prompt override: 'top {n} ports' detected — "
          f"n > 1000, using nmap default top-1000.")
    return None


# ── Flag helpers ──────────────────────────────────────────────────────────────

def sanitise_flags(flags: Optional[str]) -> str:
    if not flags:
        print(f"[*] No flags from model — using defaults: {DEFAULT_FLAGS}")
        return DEFAULT_FLAGS

    try:
        tokens = shlex.split(flags)
    except ValueError as exc:
        print(f"[!] Malformed flags ({exc}) — using defaults: {DEFAULT_FLAGS}")
        return DEFAULT_FLAGS

    safe: list[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]

        if tok == "--min-rate":
            if i + 1 < len(tokens) and re.fullmatch(r'\d+', tokens[i + 1]):
                safe.append("--min-rate")
                safe.append(tokens[i + 1])
                i += 2
            else:
                print("[!] --min-rate requires a numeric argument — skipping.")
                i += 1
            continue

        if tok == "-T5":
            print("[!] -T5 clamped to -T4 to prevent network flooding.")
            safe.append("-T4")
        elif tok in ALLOWED_FLAGS:
            safe.append(tok)
        else:
            print(f"[!] Ignoring unsafe/unknown flag: {tok!r}")
        i += 1

    if "-sA" in safe:
        reason = (
            "does not discover open ports so -sV has nothing to work on"
            if "-sV" in safe else
            "is a firewall-mapping technique, not port-discovery"
        )
        print(f"[!] -sA {reason}. Replacing with -sS.")
        safe = ["-sS" if f == "-sA" else f for f in safe]

    if not safe:
        print(f"[*] All flags were rejected — using defaults: {DEFAULT_FLAGS}")
        return DEFAULT_FLAGS

    return " ".join(safe)


# ── Nmap runner ───────────────────────────────────────────────────────────────

def _run_nmap(cmd: list[str], timeout: int = SCAN_TIMEOUT) -> Dict[str, Any]:
    """
    Execute nmap with -oX and parse XML.
    FIX I4: also extracts OS detection data from <os><osmatch> elements
    and stores it as host["os"] = "<best match name>" for correlation.
    """
    print("[*] Running:", " ".join(shlex.quote(c) for c in cmd))
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"timed_out": True, "error": f"nmap timed out after {timeout}s"}

    if proc.returncode != 0 and not proc.stdout.strip():
        print("[!] nmap stderr:", proc.stderr.strip(), file=sys.stderr)
        return {"error": proc.stderr.strip() or "nmap returned non-zero exit code"}

    if len(proc.stdout.encode()) > MAX_XML_BYTES:
        return {"error": f"nmap output exceeded {MAX_XML_BYTES // (1024*1024)} MB"}

    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(proc.stdout)
        hosts = []
        for host in root.findall("host"):
            addr   = host.find("address")
            ipaddr = addr.get("addr") if addr is not None else None
            hostdict: Dict[str, Any] = {"ip": ipaddr, "ports": []}

            # FIX I4: extract best OS match name
            os_el = host.find("os")
            if os_el is not None:
                matches = os_el.findall("osmatch")
                if matches:
                    # osmatch elements are ordered best-match first by nmap
                    hostdict["os"] = matches[0].get("name", "")

            ports_el = host.find("ports")
            if ports_el is None:
                hosts.append(hostdict)
                continue
            for p in ports_el.findall("port"):
                state_el   = p.find("state")
                service_el = p.find("service")
                hostdict["ports"].append({
                    "port":     p.get("portid"),
                    "protocol": p.get("protocol"),
                    "state":    state_el.get("state")  if state_el   is not None else None,
                    "service":  service_el.get("name") if service_el is not None else None,
                    "version":  (
                        service_el.get("version") or service_el.get("product") or None
                    ) if service_el is not None else None,
                })
            hosts.append(hostdict)
        return {"hosts": hosts}
    except ET.ParseError as exc:
        return {"error": f"XML parse error: {exc}"}
    except Exception as exc:
        return {"error": f"Unexpected parse error: {exc}"}


# ── Main scan logic ───────────────────────────────────────────────────────────

def run_nmap_direct(
    target: str,
    ports: Optional[str],
    flags: Optional[str],
    retry_on_timeout: bool = True,
) -> Dict[str, Any]:
    top_ports_flag: Optional[str] = None
    if isinstance(ports, str) and ports.startswith("__top_") and ports.endswith("__"):
        n = ports[6:-2]
        top_ports_flag = n
        ports = None
        print(f"[*] Using --top-ports {n} from prompt override.")

    ports = validate_ports(normalise_ports(ports))
    flags = sanitise_flags(flags)

    if "-sU" in flags and ports == "1-65535":
        print(f"[!] UDP full-range scan restricted to common ports: {UDP_SAFE_PORTS}")
        ports = UDP_SAFE_PORTS

    wants_version = "-sV" in flags

    def _build_disc_cmd(p: Optional[str], top_n: Optional[str] = None) -> list[str]:
        try:
            disc_tokens = [f for f in shlex.split(flags) if f != "-sV"] or ["-sS", "-Pn", "-T4"]
        except ValueError:
            disc_tokens = ["-sS", "-Pn", "-T4"]
        cmd = ["nmap", "-oX", "-"] + disc_tokens
        if top_n:
            cmd += ["--top-ports", top_n]
        elif p:
            cmd += ["-p", p]
        cmd += [target]
        return cmd

    if wants_version:
        cmd1 = _build_disc_cmd(ports, top_n=top_ports_flag)
        print("[*] Stage 1 — port discovery")

        t0 = time.monotonic()
        stage1 = _run_nmap(cmd1, timeout=_scan_timeout(target))

        if stage1.get("timed_out") and retry_on_timeout and (ports or top_ports_flag):
            print("[!] Stage 1 timed out — retrying with top 1000 ports...")
            cmd1_retry = _build_disc_cmd(None, top_n=None)
            stage1 = _run_nmap(cmd1_retry, timeout=_scan_timeout(target))

        if "error" in stage1:
            return stage1

        open_ports = list(dict.fromkeys(
            p["port"]
            for h in stage1.get("hosts", [])
            for p in h.get("ports", [])
            if p.get("state") == "open"
        ))

        if not open_ports:
            elapsed = time.monotonic() - t0
            print(f"[*] No open ports found — skipping version scan. ({elapsed:.2f}s)")
            return stage1

        print(f"[*] Stage 2 — version detection on {len(open_ports)} port(s): "
              f"{','.join(open_ports)}")

        try:
            base = [f for f in shlex.split(flags) if f != "-sV"]
        except ValueError:
            base = ["-sS", "-Pn", "-T4"]
        if "-Pn" not in base:
            base.append("-Pn")

        cmd2 = ["nmap", "-oX", "-"] + base + ["-sV", "-p", ",".join(open_ports), target]
        result = _run_nmap(cmd2, timeout=_scan_timeout(target))

        if result.get("timed_out") and retry_on_timeout:
            print("[!] Stage 2 timed out — retrying with --version-light...")
            cmd2_light = (
                ["nmap", "-oX", "-"] + base
                + ["-sV", "--version-light", "-p", ",".join(open_ports), target]
            )
            result = _run_nmap(cmd2_light, timeout=_scan_timeout(target))
            if result.get("timed_out"):
                print("[!] --version-light also timed out — using stage 1 results.")
                result = stage1

        elapsed = time.monotonic() - t0
        print(f"[*] Scan completed in {elapsed:.2f}s")
        return result

    # ── Single-stage scan ──────────────────────────────────────────────────
    t0 = time.monotonic()
    cmd = ["nmap", "-oX", "-"]
    try:
        cmd += shlex.split(flags)
    except ValueError:
        pass
    if top_ports_flag:
        cmd += ["--top-ports", top_ports_flag]
    elif ports:
        cmd += ["-p", ports]
    cmd += [target]

    result = _run_nmap(cmd, timeout=_scan_timeout(target))

    if result.get("timed_out") and retry_on_timeout and (ports or top_ports_flag):
        print("[!] Scan timed out — retrying with top 1000 ports...")
        cmd_retry = ["nmap", "-oX", "-"]
        try:
            cmd_retry += shlex.split(flags)
        except ValueError:
            pass
        cmd_retry += [target]
        result = _run_nmap(cmd_retry, timeout=_scan_timeout(target))

    elapsed = time.monotonic() - t0
    print(f"[*] Scan completed in {elapsed:.2f}s")
    return result


# ── llm-tools-nmap integration ────────────────────────────────────────────────

def run_llm_tools_nmap(target: str, ports: Optional[str], flags: Optional[str]):
    if _llm_tools is None:
        raise ImportError("llm-tools-nmap not importable")
    last_exc: Optional[Exception] = None
    for fname in ("run_scan", "nmap_scan", "scan", "do_scan"):
        if hasattr(_llm_tools, fname):
            fn = getattr(_llm_tools, fname)
            try:
                return fn(target=target, ports=ports, flags=flags)
            except TypeError:
                try:
                    return fn(target, ports, flags)
                except Exception as exc:
                    last_exc = exc
    raise RuntimeError(f"llm-tools-nmap: no working entrypoint. Last error: {last_exc}")


# ── LLM helpers ───────────────────────────────────────────────────────────────

SYSTEM_INSTRUCTION = """
You are an assistant that must produce JSON ONLY (no extra text) describing a single action.
Valid actions:
  1) {"action":"scan","target":"<ip_or_hostname>","ports":"22,80","flags":"-sS -Pn -T4"}
  2) {"action":"explain","text":"..."}
  3) {"action":"question","text":"<your question>"}

Rules for the "target" field:
  - Single IP or hostname only. No flags, spaces, or extra characters.

Rules for the "ports" field:
  - Numeric ranges only: "22,80,443" or "1-65535". Never use the word "all".

Rules for the "flags" field:
  - Use -sS for port discovery (never -sA).
  - Add -sV only when version detection is explicitly requested.
  - Always include -Pn for localhost scans.
  - Never use -T5.
"""


def normalize_ollama_response(resp: Any) -> str:
    if isinstance(resp, Iterable) and not isinstance(resp, (str, bytes, dict, list)):
        try:
            parts = []
            for chunk in resp:
                if isinstance(chunk, dict):
                    if "message" in chunk and isinstance(chunk["message"], dict) \
                            and "content" in chunk["message"]:
                        parts.append(str(chunk["message"]["content"]))
                    elif "content" in chunk:
                        parts.append(str(chunk["content"]))
                    else:
                        parts.append(json.dumps(chunk))
                else:
                    parts.append(str(chunk))
            return "".join(parts)
        except TypeError:
            pass

    if isinstance(resp, dict):
        if "message" in resp:
            m = resp["message"]
            if isinstance(m, dict):
                c = m.get("content")
                return c if isinstance(c, str) else json.dumps(c)
        if "content" in resp and isinstance(resp["content"], str):
            return resp["content"]
        if "text" in resp and isinstance(resp["text"], str):
            return resp["text"]
        return json.dumps(resp)

    if isinstance(resp, list):
        return "\n".join(
            normalize_ollama_response(i) if isinstance(i, dict) else str(i)
            for i in resp
        )

    return str(resp)


def extract_first_json(text: str) -> Optional[str]:
    start, depth = None, 0
    for i, ch in enumerate(text):
        if ch == "{":
            if start is None:
                start = i
            depth += 1
        elif ch == "}" and depth > 0:
            depth -= 1
            if depth == 0 and start is not None:
                return text[start:i + 1]
    return None


def ask_model_for_action(user_prompt: str, model_name: str) -> Dict[str, Any]:
    messages = [
        {"role": "system", "content": SYSTEM_INSTRUCTION},
        {"role": "user",   "content": user_prompt},
    ]
    resp = ollama.chat(model=model_name, messages=messages)
    text = normalize_ollama_response(resp)
    json_text = extract_first_json(text)
    if not json_text:
        raise ValueError(f"Model did not return JSON.\nRaw output:\n{text}")
    try:
        return json.loads(json_text)
    except Exception as exc:
        try:
            return json.loads(json_text.replace("'", '"'))
        except Exception:
            raise ValueError(f"Could not parse model JSON.\nRaw:\n{json_text}\nError: {exc}")


def ai_followup(result: Dict[str, Any], model_name: str) -> None:
    print("\n[*] Requesting AI follow-up analysis (open ports only)...")
    filtered = _open_ports_only(result)
    try:
        resp = ollama.chat(
            model=model_name,
            messages=[{
                "role": "user",
                "content": (
                    "Given the following network scan result (including any exploit chain), "
                    "suggest concrete attack paths and prioritised next steps for a "
                    "penetration tester:\n\n"
                    + json.dumps(filtered, indent=2)
                ),
            }],
        )
        print("\n[AI ANALYSIS]\n" + normalize_ollama_response(resp))
    except Exception as exc:
        print(f"[!] AI follow-up failed: {exc}", file=sys.stderr)


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    _load_external_intel()

    parser = argparse.ArgumentParser(description="Ollama-driven Nmap agent (v11).")
    parser.add_argument("--model",       default="dolphin-llama3:8b")
    parser.add_argument("--prompt",      help="Prompt (omit for interactive mode).")
    parser.add_argument("--yes",         action="store_true", help="Auto-confirm scans.")
    parser.add_argument("--force",       action="store_true", help="Allow non-private targets.")
    parser.add_argument("--no-intel",    action="store_true", help="Skip enrichment layer.")
    parser.add_argument("--banner",      action="store_true",
                        help="Banner-grab open ports with no nmap service ID.")
    parser.add_argument("--ai-followup", action="store_true",
                        help="Ask the model to analyse enriched results.")
    parser.add_argument(
        "--profile",
        choices=list(PROFILES),
        default="default",
        help="Scan profile (stealth / default / aggressive / udp).",
    )
    parser.add_argument(
        "--fast",
        action="store_true",
        help="Append --min-rate 1000 for faster scans.",
    )
    args = parser.parse_args()

    # ── Get user prompt ───────────────────────────────────────────────────────
    if args.prompt:
        user_prompt = args.prompt
    else:
        try:
            print("Enter what you want to do (e.g. 'Scan 127.0.0.1 for SSH and HTTP'):")
            user_prompt = input("> ").strip()
        except KeyboardInterrupt:
            print("\nInterrupted.")
            sys.exit(0)
        if not user_prompt:
            print("No prompt given.")
            sys.exit(0)

    prompt_port_override = extract_prompt_port_override(user_prompt)

    # ── Parse model action ────────────────────────────────────────────────────
    try:
        action = ask_model_for_action(user_prompt, model_name=args.model)
    except Exception as exc:
        print("ERROR:", exc, file=sys.stderr)
        sys.exit(1)

    print("[*] Model action:", action)

    if action.get("action") == "question":
        print("[MODEL QUESTION]", action.get("text"))
        sys.exit(0)

    if action.get("action") == "explain":
        print("[MODEL EXPLANATION]\n", action.get("text"))
        sys.exit(0)

    if action.get("action") != "scan":
        print("Unknown action:", action.get("action"))
        sys.exit(1)

    target = (action.get("target") or "").strip()
    flags  = action.get("flags")

    if prompt_port_override == "NONE":
        ports = action.get("ports")
    else:
        ports = prompt_port_override
        print(f"[*] Port override applied from prompt: {ports!r}")

    if not target:
        print("No target from model.")
        sys.exit(1)

    if not target_allowed(target, force=args.force):
        print(f"[!] Refusing to scan '{target}'. Use --force to override.")
        sys.exit(1)

    flags = apply_profile(flags, args.profile)

    if args.fast:
        flags = flags + " --min-rate 1000"
        print(f"[*] --fast enabled: appended '--min-rate 1000'. Flags: {flags}")

    flags = sanitise_flags(flags)

    if not args.yes:
        print(f"\nAbout to scan: target={target}  ports={ports}  flags={flags}")
        print("Type 'yes' to continue:")
        if input("> ").strip().lower() not in ("y", "yes"):
            print("Aborted.")
            sys.exit(0)

    # ── Run scan ──────────────────────────────────────────────────────────────
    if _llm_tools is not None:
        try:
            print("[*] Trying llm-tools-nmap integration...")
            res = run_llm_tools_nmap(target=target, ports=ports, flags=flags)
            print("[*] llm-tools-nmap result:")
            print(json.dumps(res, indent=2))
            sys.exit(0)
        except Exception as exc:
            print(f"[!] llm-tools-nmap failed: {exc} — falling back.", file=sys.stderr)

    res = run_nmap_direct(target=target, ports=ports, flags=flags)

    # ── Post-scan pipeline ────────────────────────────────────────────────────
    if not args.no_intel:

        # Step 1 — Initial enrichment
        res = enrich_results(res)

        if args.banner and "error" not in res:
            # Step 2 — Concurrent banner grabbing
            print("\n[*] Banner grabbing services without full identification...")
            res = banner_grab_scan(res)

            # Step 3 — Concurrent fingerprinting
            print("\n[*] Applying service fingerprinting engine...")
            res = apply_fingerprinting(res)

            # Step 4 — Re-enrich after fingerprinting
            print("\n[*] Re-enriching after fingerprinting...")
            res = enrich_results(res)

        # Step 5 — OS fingerprint correlation (FIX I4)
        print("\n[*] Applying OS fingerprint correlation...")
        res = apply_os_correlation(res)

        # Step 6 — Exploit chain construction (FIX I5)
        print("\n[*] Building exploit chain...")
        res = build_exploit_chain(res)

        # Step 7 — Human-readable exposure summary
        print_exposure_summary(res)
        print("\n[*] Enriched result:")

    else:
        if args.banner and "error" not in res:
            print("\n[*] Banner grabbing services without full identification...")
            res = banner_grab_scan(res)
            print("\n[*] Applying service fingerprinting engine...")
            res = apply_fingerprinting(res)
        print("\n[*] Raw result:")

    print(json.dumps(res, indent=2))

    audit_log(target, res)

    if args.ai_followup and "error" not in res:
        ai_followup(res, model_name=args.model)


if __name__ == "__main__":
    main()