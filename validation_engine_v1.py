#!/usr/bin/env python3
"""
Validation Engine v1 — consent-based exposure verification.

Integrates with the v11 nmap_agent_v11.py pipeline as a post-scan layer.
Replaces the "attack chain" concept with evidence-collection checks that:
  - require explicit scope approval before any active probing
  - run read-only, non-destructive checks only
  - collect evidence snippets (not exploits)
  - produce prioritised remediation guidance
  - log everything for audit / stakeholder reports

Usage (standalone):
    python3 validation_engine_v1.py --target 127.0.0.1 [--report report.json]

Usage (integrated with v11 scan output):
    python3 validation_engine_v1.py --from-scan scan_result.json [--report out.json]

Architecture:
    Scan result (from v11)
        ↓
    Scope gate          ← require written authorisation
        ↓
    Validator           ← non-destructive checks per service
        ↓
    Evidence collector  ← captures snippets, redacts secrets
        ↓
    Remediation engine  ← prioritised fix guidance
        ↓
    JSON + HTML report  ← shareable with stakeholders
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

# ── Constants ─────────────────────────────────────────────────────────────────

VERSION          = "1.0"
SCOPE_FILE       = "approved_scope.json"   # editable by operator
VALIDATION_LOG   = os.path.expanduser("~/validation_audit.log")
CHECK_TIMEOUT    = 5      # seconds per individual check
CHECK_WORKERS    = 10     # concurrent check threads
MAX_SNIPPET_LEN  = 300    # chars kept from command stdout

# Services that should NEVER be actively probed without explicit flag
SENSITIVE_SERVICES = {"rdp", "mssql", "ldap", "snmp"}

# ── Scope management ──────────────────────────────────────────────────────────

def load_scope() -> Dict[str, Any]:
    """
    Load approved_scope.json.  If absent, return an empty scope.
    Schema:
    {
      "targets": ["127.0.0.1", "192.168.1.0/24"],
      "approved_by": "John Smith",
      "approved_at": "2025-01-01T00:00:00Z",
      "expires_at":  "2025-12-31T00:00:00Z",
      "notes": "Internal lab only"
    }
    """
    try:
        with open(SCOPE_FILE) as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return {}
        return data
    except FileNotFoundError:
        return {}
    except (json.JSONDecodeError, OSError) as exc:
        print(f"[!] Could not load scope file: {exc}", file=sys.stderr)
        return {}


def _ip_in_cidr(ip: str, cidr: str) -> bool:
    """Return True if ip falls within cidr (e.g. '192.168.1.0/24')."""
    import ipaddress
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def in_scope(target: str, scope: Dict[str, Any]) -> bool:
    """
    Check whether target is covered by the loaded scope document.
    Supports exact IP/hostname match and CIDR notation.
    """
    approved = scope.get("targets", [])
    for entry in approved:
        if entry == target:
            return True
        if "/" in entry and _ip_in_cidr(target, entry):
            return True
    return False


def scope_is_expired(scope: Dict[str, Any]) -> bool:
    expires = scope.get("expires_at")
    if not expires:
        return False
    try:
        exp = datetime.datetime.fromisoformat(expires.replace("Z", "+00:00"))
        return datetime.datetime.now(datetime.timezone.utc) > exp
    except ValueError:
        return False


def require_approval(target: str) -> None:
    """
    Hard gate: raises PermissionError if the target is not in the approved
    scope file, or if the scope has expired.
    Prints a clear message directing the operator to update approved_scope.json.
    """
    scope = load_scope()

    if not scope:
        raise PermissionError(
            f"No scope file found at '{SCOPE_FILE}'.\n"
            "Create it with at least:\n"
            '  {"targets": ["<ip>"], "approved_by": "Name", '
            '"approved_at": "ISO-timestamp"}'
        )

    if scope_is_expired(scope):
        raise PermissionError(
            f"Scope document expired at {scope.get('expires_at')}. "
            "Renew authorisation before running active checks."
        )

    if not in_scope(target, scope):
        raise PermissionError(
            f"Target '{target}' is NOT in the approved scope.\n"
            f"Approved targets: {scope.get('targets', [])}\n"
            f"Approved by: {scope.get('approved_by', 'unknown')}\n"
            "Add the target to approved_scope.json to proceed."
        )

    approved_by = scope.get("approved_by", "unknown")
    approved_at = scope.get("approved_at", "unknown")
    print(f"[✓] Scope gate passed: '{target}' approved by {approved_by} on {approved_at}")


# ── Validation check definitions ──────────────────────────────────────────────
#
# Each check is a dict:
#   name        — short identifier
#   description — human-readable purpose
#   cmd         — shell command template; {host} and {port} are substituted
#   evidence    — string or list[str]; presence in stdout = exposure confirmed
#   severity    — "critical" | "high" | "medium" | "low"
#   safe        — True = always run; False = requires --aggressive flag
#
# ALL commands are:
#   - read-only (no writes, no config changes)
#   - single-packet or short-lived
#   - output-capped by MAX_SNIPPET_LEN
#
# Commands use portable POSIX tools available on most Linux/macOS systems.
# Windows targets: use --from-scan with scan_result.json; checks skip
# automatically when the tool (nc, curl, openssl) is absent.

VALIDATION_CHECKS: Dict[str, List[Dict[str, Any]]] = {
    "ftp": [
        {
            "name":        "anonymous_login",
            "description": "Test whether FTP allows anonymous access without credentials.",
            "cmd":         "printf 'USER anonymous\\r\\nPASS anonymous@\\r\\nQUIT\\r\\n' "
                           "| nc -w{timeout} {host} {port}",
            "evidence":    ["230 ", "230-"],   # 230 = login successful
            "severity":    "high",
            "safe":        True,
        },
        {
            "name":        "banner_grab",
            "description": "Capture FTP service banner for version identification.",
            "cmd":         "printf 'QUIT\\r\\n' | nc -w{timeout} {host} {port}",
            "evidence":    ["220"],            # 220 = service ready
            "severity":    "low",
            "safe":        True,
        },
    ],
    "smtp": [
        {
            "name":        "open_relay_test",
            "description": "Check whether SMTP will forward mail to external domains (open relay).",
            "cmd":         "printf 'EHLO probe.test\\r\\nMAIL FROM:<test@probe.test>\\r\\n"
                           "RCPT TO:<check@external.example>\\r\\nQUIT\\r\\n' "
                           "| nc -w{timeout} {host} {port}",
            "evidence":    ["250 2.1.5", "250 ok"],  # relay accepted
            "severity":    "high",
            "safe":        True,
        },
        {
            "name":        "user_enum_vrfy",
            "description": "Test VRFY command for user enumeration.",
            "cmd":         "printf 'VRFY root\\r\\nQUIT\\r\\n' | nc -w{timeout} {host} {port}",
            "evidence":    ["250 ", "252 "],   # 250/252 = user exists
            "severity":    "medium",
            "safe":        True,
        },
    ],
    "http": [
        {
            "name":        "security_headers",
            "description": "Check for missing HTTP security headers.",
            "cmd":         "curl -sk --max-time {timeout} -I http://{host}:{port}/",
            "evidence":    ["x-frame-options", "content-security-policy",
                            "strict-transport-security", "x-content-type-options"],
            "severity":    "medium",
            "safe":        True,
            # evidence presence = good; absence = the finding
            "invert":      True,   # flag raised when evidence is ABSENT
        },
        {
            "name":        "server_banner_disclosure",
            "description": "Detect verbose Server: header disclosing framework/version.",
            "cmd":         "curl -sk --max-time {timeout} -I http://{host}:{port}/",
            "evidence":    ["server: apache", "server: nginx", "server: iis",
                            "x-powered-by:", "x-aspnet-version:"],
            "severity":    "low",
            "safe":        True,
        },
        {
            "name":        "directory_listing",
            "description": "Check for open directory listing on common paths.",
            "cmd":         "curl -sk --max-time {timeout} http://{host}:{port}/",
            "evidence":    ["index of /", "directory listing", "parent directory"],
            "severity":    "medium",
            "safe":        True,
        },
    ],
    "https": [
        {
            "name":        "tls_version",
            "description": "Detect legacy TLS versions (TLS 1.0 / TLS 1.1).",
            "cmd":         "openssl s_client -connect {host}:{port} "
                           "-tls1 -brief < /dev/null 2>&1",
            "evidence":    ["cipher", "handshake"],
            "severity":    "high",
            "safe":        True,
        },
        {
            "name":        "certificate_expiry",
            "description": "Check TLS certificate expiry and subject.",
            "cmd":         "openssl s_client -connect {host}:{port} < /dev/null 2>&1 "
                           "| openssl x509 -noout -dates -subject 2>&1",
            "evidence":    ["notafter", "subject"],
            "severity":    "low",
            "safe":        True,
        },
        {
            "name":        "security_headers_tls",
            "description": "Check for missing HTTPS security headers (HSTS etc.).",
            "cmd":         "curl -sk --max-time {timeout} -I https://{host}:{port}/",
            "evidence":    ["strict-transport-security"],
            "severity":    "medium",
            "safe":        True,
            "invert":      True,
        },
    ],
    "ssh": [
        {
            "name":        "banner_grab",
            "description": "Capture SSH protocol banner for version identification.",
            "cmd":         "nc -w{timeout} {host} {port}",
            "evidence":    ["ssh-"],
            "severity":    "low",
            "safe":        True,
        },
    ],
    "redis": [
        {
            "name":        "unauthenticated_ping",
            "description": "Check whether Redis responds to PING without authentication.",
            "cmd":         "printf 'PING\\r\\n' | nc -w{timeout} {host} {port}",
            "evidence":    ["+pong"],
            "severity":    "critical",
            "safe":        True,
        },
        {
            "name":        "config_get_dir",
            "description": "Read Redis working directory (indicates full CONFIG access).",
            "cmd":         "printf 'CONFIG GET dir\\r\\n' | nc -w{timeout} {host} {port}",
            "evidence":    ["$"],              # bulk string reply = command accepted
            "severity":    "critical",
            "safe":        True,
        },
    ],
    "mysql": [
        {
            "name":        "handshake_banner",
            "description": "Capture MySQL greeting packet to confirm exposure and version.",
            "cmd":         "nc -w{timeout} {host} {port} < /dev/null",
            "evidence":    ["mysql", "mariadb", "5.", "8."],
            "severity":    "high",
            "safe":        True,
        },
    ],
    "postgresql": [
        {
            "name":        "handshake_banner",
            "description": "Probe PostgreSQL port; an error response confirms exposure.",
            "cmd":         "printf '\\x00\\x00\\x00\\x08\\x04\\xd2\\x16\\x2f' "
                           "| nc -w{timeout} {host} {port}",
            "evidence":    ["E", "pg"],        # error or version string
            "severity":    "high",
            "safe":        True,
        },
    ],
    "mongodb": [
        {
            "name":        "unauthenticated_access",
            "description": "Check if MongoDB port responds without credentials.",
            "cmd":         "nc -w{timeout} {host} {port} < /dev/null",
            "evidence":    ["ismaster", "mongodb", "version"],
            "severity":    "critical",
            "safe":        True,
        },
    ],
    "elasticsearch": [
        {
            "name":        "cluster_info",
            "description": "Check if Elasticsearch responds to unauthenticated REST query.",
            "cmd":         "curl -sk --max-time {timeout} http://{host}:{port}/",
            "evidence":    ["cluster_name", "version", "tagline"],
            "severity":    "critical",
            "safe":        True,
        },
        {
            "name":        "index_list",
            "description": "Enumerate indices (confirms read access to all data).",
            "cmd":         "curl -sk --max-time {timeout} http://{host}:{port}/_cat/indices",
            "evidence":    ["open", "green", "yellow"],
            "severity":    "critical",
            "safe":        True,
        },
    ],
    "dns": [
        {
            "name":        "zone_transfer",
            "description": "Attempt AXFR zone transfer.",
            "cmd":         "dig axfr @{host} {host} +time={timeout}",
            "evidence":    ["transfer failed", "xfr size"],  # xfr size = success
            "severity":    "high",
            "safe":        True,
        },
        {
            "name":        "open_recursion",
            "description": "Test whether the resolver allows recursive queries from outside.",
            "cmd":         "dig @{host} google.com +time={timeout} +short",
            "evidence":    [".", "0.0.0.0"],   # any answer = recursion allowed
            "severity":    "medium",
            "safe":        True,
        },
    ],
    "smtp": [
        {
            "name":        "open_relay_test",
            "description": "Check whether SMTP will forward mail to external domains.",
            "cmd":         "printf 'EHLO probe.test\\r\\nMAIL FROM:<test@probe.test>\\r\\n"
                           "RCPT TO:<check@external.example>\\r\\nQUIT\\r\\n' "
                           "| nc -w{timeout} {host} {port}",
            "evidence":    ["250 2.1.5", "250 ok"],
            "severity":    "high",
            "safe":        True,
        },
    ],
    "smb": [
        {
            "name":        "port_reachable",
            "description": "Confirm SMB port is reachable (smbclient required for full enum).",
            "cmd":         "nc -w{timeout} -z {host} {port} && echo reachable",
            "evidence":    ["reachable"],
            "severity":    "high",
            "safe":        True,
        },
    ],
    "microsoft-ds": [
        {
            "name":        "port_reachable",
            "description": "Confirm SMB/445 is reachable.",
            "cmd":         "nc -w{timeout} -z {host} {port} && echo reachable",
            "evidence":    ["reachable"],
            "severity":    "high",
            "safe":        True,
        },
    ],
    "ollama": [
        {
            "name":        "binding_check",
            "description": "Check if Ollama is listening on non-loopback interface.",
            "cmd":         "curl -sk --max-time {timeout} http://{host}:{port}/api/tags",
            "evidence":    ["models", "name"],
            "severity":    "medium",
            "safe":        True,
        },
    ],
    "http-alt": [
        {
            "name":        "service_identify",
            "description": "Identify service on alternate HTTP port.",
            "cmd":         "curl -sk --max-time {timeout} -I http://{host}:{port}/",
            "evidence":    ["200", "301", "302", "server:"],
            "severity":    "medium",
            "safe":        True,
        },
    ],
    "telnet": [
        {
            "name":        "banner_grab",
            "description": "Capture Telnet banner — presence alone is a critical finding.",
            "cmd":         "nc -w{timeout} {host} {port}",
            "evidence":    [],    # any response = exposure confirmed
            "severity":    "critical",
            "safe":        True,
        },
    ],
}

# ── Remediation guidance ──────────────────────────────────────────────────────

REMEDIATION: Dict[str, Dict[str, str]] = {
    "ftp": {
        "anonymous_login":         "Disable anonymous FTP login. Enforce TLS (FTPS) "
                                   "or migrate to SFTP over SSH.",
        "banner_grab":             "Suppress FTP version banner (server_min_id setting). "
                                   "Ensure FTP is necessary — prefer SFTP.",
    },
    "smtp": {
        "open_relay_test":         "Restrict SMTP relay to authenticated senders only. "
                                   "Configure mynetworks / relay restrictions in Postfix/Exim.",
        "user_enum_vrfy":          "Disable VRFY and EXPN commands "
                                   "(smtpd_disable_vrfy_command=yes in Postfix).",
    },
    "http": {
        "security_headers":        "Add headers: X-Frame-Options: DENY, "
                                   "Content-Security-Policy, X-Content-Type-Options: nosniff, "
                                   "Strict-Transport-Security (if HTTPS available).",
        "server_banner_disclosure":"Suppress Server: header (ServerTokens Prod / server_tokens off). "
                                   "Remove X-Powered-By and X-AspNet-Version headers.",
        "directory_listing":       "Disable directory listing "
                                   "(Options -Indexes in Apache / autoindex off in Nginx).",
    },
    "https": {
        "tls_version":             "Disable TLS 1.0 and TLS 1.1. Enforce TLS 1.2+ only. "
                                   "Use testssl.sh to audit cipher suite strength.",
        "certificate_expiry":      "Monitor certificate expiry with automated alerts "
                                   "(e.g. Certbot, Let's Encrypt auto-renew, Zabbix).",
        "security_headers_tls":    "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "ssh": {
        "banner_grab":             "Use Protocol 2 only. Disable root login "
                                   "(PermitRootLogin no). Enforce key-based auth.",
    },
    "redis": {
        "unauthenticated_ping":    "Bind Redis to 127.0.0.1 (bind 127.0.0.1 in redis.conf). "
                                   "Set a strong requirepass. Enable ACL if Redis 6+.",
        "config_get_dir":          "Disable CONFIG command for untrusted clients "
                                   "(rename-command CONFIG '' in redis.conf).",
    },
    "mysql": {
        "handshake_banner":        "Bind MySQL to 127.0.0.1 (bind-address=127.0.0.1). "
                                   "Remove anonymous accounts (mysql.user). "
                                   "Enforce strong passwords via validate_password plugin.",
    },
    "postgresql": {
        "handshake_banner":        "Set listen_addresses=localhost in postgresql.conf. "
                                   "Review pg_hba.conf — remove 'trust' auth. "
                                   "Use scram-sha-256 for all connections.",
    },
    "mongodb": {
        "unauthenticated_access":  "Enable --auth flag. Create admin user immediately. "
                                   "Bind to localhost (net.bindIp: 127.0.0.1). "
                                   "Enable TLS (net.tls.mode: requireTLS).",
    },
    "elasticsearch": {
        "cluster_info":            "Enable X-Pack security (xpack.security.enabled: true). "
                                   "Set up TLS for transport and HTTP layers. "
                                   "Create roles and users — never leave default open.",
        "index_list":              "Review index ACLs immediately. "
                                   "Disable public HTTP access via firewall rule.",
    },
    "dns": {
        "zone_transfer":           "Restrict AXFR to authorised secondaries only "
                                   "(allow-transfer { trusted_secondaries; }; in BIND).",
        "open_recursion":          "Disable open recursion (recursion no; or allow-recursion { localnets; }; in BIND).",
    },
    "smb": {
        "port_reachable":          "Block SMB (139/445) at the perimeter. "
                                   "Enable SMB signing. Disable SMBv1 (Set-SmbServerConfiguration "
                                   "-EnableSMB1Protocol $false).",
    },
    "microsoft-ds": {
        "port_reachable":          "Block SMB/445 at the perimeter. "
                                   "Enable SMB signing. Patch MS17-010 (EternalBlue) if unpatched.",
    },
    "ollama": {
        "binding_check":           "Bind Ollama to 127.0.0.1 only "
                                   "(OLLAMA_HOST=127.0.0.1 environment variable). "
                                   "Place behind an authenticated reverse proxy if external access is needed.",
    },
    "http-alt": {
        "service_identify":        "Identify and harden the service on this port. "
                                   "Remove if not required. Add authentication if it is an admin panel.",
    },
    "telnet": {
        "banner_grab":             "Disable Telnet immediately. Replace with SSH. "
                                   "Block port 23 at the firewall as an interim measure.",
    },
}

# ── Execution wrapper ─────────────────────────────────────────────────────────

def _tool_available(name: str) -> bool:
    """Return True if an external tool is on PATH."""
    return subprocess.run(
        ["which", name], capture_output=True
    ).returncode == 0


def run_check(
    cmd: str,
    timeout: int = CHECK_TIMEOUT,
) -> Dict[str, Any]:
    """
    Execute a single validation command with a hard timeout.
    Returns a result dict with stdout snippet, exit code, and timing.
    Sensitive data patterns (passwords, tokens) are redacted from output.
    """
    t0 = time.time()
    try:
        proc = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout + 1,   # +1 s buffer over the nc/curl timeout
        )
        raw = (proc.stdout + proc.stderr)[:MAX_SNIPPET_LEN * 2]
        snippet = _redact(raw)[:MAX_SNIPPET_LEN]
        return {
            "ok":      True,
            "stdout":  snippet,
            "rc":      proc.returncode,
            "elapsed": round(time.time() - t0, 2),
        }
    except subprocess.TimeoutExpired:
        return {
            "ok":      False,
            "error":   "timeout",
            "elapsed": round(time.time() - t0, 2),
        }
    except Exception as exc:
        return {
            "ok":      False,
            "error":   str(exc),
            "elapsed": round(time.time() - t0, 2),
        }


# Patterns that should never appear in evidence snippets
_REDACT_RE = re.compile(
    r'(password|passwd|secret|token|key|auth)\s*[=:]\s*\S+',
    re.IGNORECASE,
)


def _redact(text: str) -> str:
    return _REDACT_RE.sub(r'\1=<REDACTED>', text)


# ── Evidence matching ─────────────────────────────────────────────────────────

def _evidence_hit(check: Dict[str, Any], stdout: str) -> bool:
    """
    Return True when the check's evidence condition is met.
    Supports:
      - empty evidence list  → any response = hit
      - list of strings      → any string found in stdout (case-insensitive)
      - "invert" flag        → hit when evidence is ABSENT (used for header checks)
    """
    evidence = check.get("evidence", [])
    invert   = check.get("invert", False)
    lower    = stdout.lower()

    if not evidence:
        # Any non-empty response confirms exposure
        hit = bool(stdout.strip())
    else:
        hit = any(e.lower() in lower for e in evidence)

    return (not hit) if invert else hit


# ── Validator ─────────────────────────────────────────────────────────────────

def _run_one_check(
    host_ip: str,
    port_num: str,
    service: str,
    check: Dict[str, Any],
    aggressive: bool,
) -> Dict[str, Any]:
    """
    Execute a single check and return a result record.
    Called from the thread pool.
    """
    if not check.get("safe", True) and not aggressive:
        return {
            "port":             port_num,
            "service":          service,
            "check":            check["name"],
            "description":      check["description"],
            "severity":         check["severity"],
            "skipped":          True,
            "skip_reason":      "Requires --aggressive flag",
            "confirmed":        False,
            "evidence_snippet": "",
            "remediation":      "",
        }

    cmd = check["cmd"].format(
        host=host_ip,
        port=port_num,
        timeout=CHECK_TIMEOUT,
    )

    result = run_check(cmd, timeout=CHECK_TIMEOUT)
    stdout  = result.get("stdout", "")
    confirmed = False

    if result.get("ok") or result.get("stdout"):
        confirmed = _evidence_hit(check, stdout)

    remediation = (
        REMEDIATION
        .get(service, {})
        .get(check["name"], "Investigate and harden configuration.")
    )

    return {
        "port":             port_num,
        "service":          service,
        "check":            check["name"],
        "description":      check["description"],
        "severity":         check["severity"],
        "skipped":          False,
        "confirmed":        confirmed,
        "evidence_snippet": stdout if confirmed else "",
        "elapsed":          result.get("elapsed", 0),
        "remediation":      remediation if confirmed else "",
    }


def validate_host(
    host: Dict[str, Any],
    aggressive: bool = False,
) -> List[Dict[str, Any]]:
    """
    Run all applicable validation checks for a host concurrently.
    Returns a flat list of check result dicts.
    """
    ip      = host.get("ip", "")
    results: List[Dict[str, Any]] = []
    tasks:   List[Tuple]          = []

    for port in host.get("ports", []):
        if port.get("state") != "open":
            continue
        service   = (port.get("service") or "").lower().strip()
        port_num  = str(port.get("port", ""))

        if service in SENSITIVE_SERVICES and not aggressive:
            print(f"  [skip] {service}:{port_num} — sensitive service, "
                  "use --aggressive to probe")
            continue

        checks = VALIDATION_CHECKS.get(service, [])
        if not checks:
            print(f"  [skip] {service}:{port_num} — no checks defined")
            continue

        for check in checks:
            tasks.append((ip, port_num, service, check))

    if not tasks:
        return results

    print(f"[*] Running {len(tasks)} validation check(s) on {ip} "
          f"(workers={CHECK_WORKERS})...")

    with ThreadPoolExecutor(max_workers=CHECK_WORKERS) as ex:
        futures = {
            ex.submit(_run_one_check, ip, port_num, svc, chk, aggressive): (ip, port_num, svc, chk)
            for ip, port_num, svc, chk in tasks
        }
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as exc:
                ip, port_num, svc, chk = futures[future]
                print(f"  [!] Check failed ({svc}:{port_num} / {chk['name']}): {exc}",
                      file=sys.stderr)

    # Sort: confirmed → severity → service
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    results.sort(key=lambda r: (
        0 if r.get("confirmed") else 1,
        sev_order.get(r.get("severity", "low"), 3),
        r.get("service", ""),
    ))

    return results


# ── Remediation summary ───────────────────────────────────────────────────────

def build_remediation_summary(checks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Filter to confirmed findings only, deduplicate by service+check,
    and return prioritised remediation items.
    """
    seen  = set()
    items = []
    for c in checks:
        if not c.get("confirmed"):
            continue
        key = (c["service"], c["check"])
        if key in seen:
            continue
        seen.add(key)
        items.append({
            "severity":    c["severity"],
            "service":     c["service"],
            "port":        c["port"],
            "issue":       c["check"],
            "description": c["description"],
            "remediation": c["remediation"],
        })
    return items


# ── Audit log ─────────────────────────────────────────────────────────────────

def _validation_audit_log(
    target: str,
    checks: List[Dict[str, Any]],
    summary: List[Dict[str, Any]],
) -> None:
    entry = {
        "timestamp":   datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "target":      target,
        "total":       len(checks),
        "confirmed":   sum(1 for c in checks if c.get("confirmed")),
        "skipped":     sum(1 for c in checks if c.get("skipped")),
        "summary":     summary,
    }
    try:
        with open(VALIDATION_LOG, "a") as fh:
            fh.write(json.dumps(entry) + "\n")
        print(f"[*] Validation audit written → {VALIDATION_LOG}")
    except OSError as exc:
        print(f"[!] Could not write validation audit: {exc}", file=sys.stderr)


# ── Report generation ─────────────────────────────────────────────────────────

def _report_checksum(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()[:16]


def generate_json_report(
    target: str,
    scan_result: Dict[str, Any],
    all_checks: Dict[str, List[Dict[str, Any]]],
    all_summaries: Dict[str, List[Dict[str, Any]]],
    path: str,
) -> None:
    payload = {
        "report_version":  VERSION,
        "generated_at":    datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "target":          target,
        "scan_summary":    {
            h["ip"]: {
                "open_ports": [
                    {"port": p["port"], "service": p.get("service"), "risk": p.get("risk")}
                    for p in h.get("ports", []) if p.get("state") == "open"
                ],
                "os":         h.get("os"),
                "chain":      h.get("chain_of_attack"),
            }
            for h in scan_result.get("hosts", [])
        },
        "validations":     all_checks,
        "remediation":     all_summaries,
    }
    raw = json.dumps(payload, indent=2)
    payload["checksum"] = _report_checksum(raw)

    try:
        with open(path, "w") as fh:
            json.dump(payload, fh, indent=2)
        print(f"[*] JSON report saved → {path}")
    except OSError as exc:
        print(f"[!] Could not write JSON report: {exc}", file=sys.stderr)


def generate_html_report(
    target: str,
    all_checks: Dict[str, List[Dict[str, Any]]],
    all_summaries: Dict[str, List[Dict[str, Any]]],
    path: str,
) -> None:
    """Generate a self-contained HTML report for stakeholder sharing."""

    sev_colors = {
        "critical": "#c0392b",
        "high":     "#e67e22",
        "medium":   "#f1c40f",
        "low":      "#27ae60",
    }

    rows = []
    for host_ip, checks in all_checks.items():
        for c in checks:
            if not c.get("confirmed"):
                continue
            color = sev_colors.get(c.get("severity", "low"), "#888")
            snippet = (c.get("evidence_snippet") or "").replace("<", "&lt;").replace(">", "&gt;")
            rows.append(f"""
        <tr>
          <td>{host_ip}</td>
          <td>{c['port']}</td>
          <td>{c['service']}</td>
          <td>{c['check']}</td>
          <td style="color:{color};font-weight:bold">{c.get('severity','').upper()}</td>
          <td><code>{snippet[:200]}</code></td>
          <td>{c.get('remediation','')}</td>
        </tr>""")

    table_body = "\n".join(rows) if rows else "<tr><td colspan='7'>No confirmed exposures.</td></tr>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Validation Report — {target}</title>
<style>
  body  {{ font-family: Arial, sans-serif; margin: 2em; background: #f9f9f9; }}
  h1    {{ color: #2c3e50; }}
  table {{ border-collapse: collapse; width: 100%; background: #fff; }}
  th    {{ background: #2c3e50; color: #fff; padding: 8px; text-align: left; }}
  td    {{ border: 1px solid #ddd; padding: 8px; vertical-align: top; }}
  tr:nth-child(even) {{ background: #f2f2f2; }}
  code  {{ font-size: 0.85em; background: #eee; padding: 2px 4px; border-radius: 3px;
           word-break: break-all; }}
  .meta {{ color: #666; font-size: 0.9em; margin-bottom: 1em; }}
</style>
</head>
<body>
<h1>🔍 Validation Report</h1>
<p class="meta">
  Target: <strong>{target}</strong> &nbsp;|&nbsp;
  Generated: <strong>{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</strong>
</p>
<table>
  <thead>
    <tr>
      <th>Host</th><th>Port</th><th>Service</th><th>Check</th>
      <th>Severity</th><th>Evidence snippet</th><th>Remediation</th>
    </tr>
  </thead>
  <tbody>
    {table_body}
  </tbody>
</table>
</body>
</html>"""

    try:
        with open(path, "w") as fh:
            fh.write(html)
        print(f"[*] HTML report saved → {path}")
    except OSError as exc:
        print(f"[!] Could not write HTML report: {exc}", file=sys.stderr)


# ── Console summary ───────────────────────────────────────────────────────────

def print_validation_summary(
    host_ip: str,
    checks: List[Dict[str, Any]],
    summary: List[Dict[str, Any]],
) -> None:
    confirmed = [c for c in checks if c.get("confirmed")]
    skipped   = [c for c in checks if c.get("skipped")]

    print(f"\n{'='*60}")
    print(f"[VALIDATION SUMMARY] {host_ip}")
    print(f"{'='*60}")
    print(f"  Total checks : {len(checks)}")
    print(f"  Confirmed    : {len(confirmed)}")
    print(f"  Skipped      : {len(skipped)}")

    if not confirmed:
        print("  → No exposures confirmed by active checks.")
        return

    print(f"\n  CONFIRMED FINDINGS:")
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for c in sorted(confirmed, key=lambda x: sev_order.get(x.get("severity", "low"), 3)):
        sev = c.get("severity", "").upper()
        print(f"  [{sev:8s}] {c['service']}:{c['port']} / {c['check']}")
        print(f"             ↳ {c['description']}")
        if c.get("evidence_snippet"):
            snippet = c["evidence_snippet"][:80].replace("\n", " ")
            print(f"             evidence: {snippet!r}")
        if c.get("remediation"):
            print(f"             fix:      {c['remediation'][:100]}...")
        print()


# ── Integration hook ──────────────────────────────────────────────────────────

def run_validation_pipeline(
    scan_result: Dict[str, Any],
    target: str,
    aggressive: bool = False,
    report_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Main entry point for integration with v11 pipeline.
    Call after enrich_results() and build_exploit_chain().

    Returns the scan_result dict enriched with validation data per host.
    """
    # Scope gate — hard stop if not authorised
    require_approval(target)

    all_checks:    Dict[str, List[Dict[str, Any]]] = {}
    all_summaries: Dict[str, List[Dict[str, Any]]] = {}

    for host in scan_result.get("hosts", []):
        ip = host.get("ip", "")
        print(f"\n[*] Validating host: {ip}")

        checks  = validate_host(host, aggressive=aggressive)
        summary = build_remediation_summary(checks)

        host["validations"]        = checks
        host["remediation_summary"] = summary

        all_checks[ip]    = checks
        all_summaries[ip] = summary

        print_validation_summary(ip, checks, summary)
        _validation_audit_log(ip, checks, summary)

    if report_path:
        json_path = report_path if report_path.endswith(".json") else report_path + ".json"
        html_path = json_path.replace(".json", ".html")
        generate_json_report(target, scan_result, all_checks, all_summaries, json_path)
        generate_html_report(target, all_checks, all_summaries, html_path)

    return scan_result


# ── CLI (standalone mode) ─────────────────────────────────────────────────────

def _build_mock_scan_result(target: str) -> Dict[str, Any]:
    """
    Quick port probe to build a minimal scan result when run standalone
    (without a v11 JSON file).  Uses socket connect — no nmap needed.
    This is intentionally limited; use v11 for full scan quality.
    """
    import ipaddress

    QUICK_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587,
                   993, 995, 1433, 3306, 3389, 5432, 5900, 6379,
                   8080, 8443, 9200, 11434, 27017]

    ports_found = []
    print(f"[*] Quick port probe on {target} (no nmap)...")
    for p in QUICK_PORTS:
        try:
            with socket.create_connection((target, p), timeout=1.0):
                print(f"  open: {p}")
                ports_found.append({
                    "port":    str(p),
                    "state":   "open",
                    "service": None,
                    "version": None,
                })
        except OSError:
            pass

    return {"hosts": [{"ip": target, "ports": ports_found}]}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validation Engine v1 — consent-based exposure verification."
    )
    parser.add_argument("--target",      help="Target IP (required when not using --from-scan).")
    parser.add_argument("--from-scan",   metavar="FILE",
                        help="Load scan result JSON from v11 pipeline.")
    parser.add_argument("--report",      metavar="FILE",
                        help="Output path for JSON + HTML report (without extension).")
    parser.add_argument("--aggressive",  action="store_true",
                        help="Also probe sensitive services (SNMP, LDAP, RDP, MSSQL).")
    parser.add_argument("--init-scope",  action="store_true",
                        help="Create a template approved_scope.json and exit.")
    args = parser.parse_args()

    # ── Scaffold scope file ───────────────────────────────────────────────────
    if args.init_scope:
        template = {
            "targets":     ["127.0.0.1"],
            "approved_by": "Your Name",
            "approved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "expires_at":  (
                datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(days=90)
            ).isoformat(),
            "notes":       "Internal lab — replace with actual scope.",
        }
        with open(SCOPE_FILE, "w") as fh:
            json.dump(template, fh, indent=2)
        print(f"[*] Scope template created: {SCOPE_FILE}")
        print("    Edit 'targets' and 'approved_by' before running active checks.")
        sys.exit(0)

    # ── Load or build scan result ─────────────────────────────────────────────
    if args.from_scan:
        try:
            with open(args.from_scan) as fh:
                scan_result = json.load(fh)
            # Derive target from first host IP if not specified
            target = args.target or (
                scan_result.get("hosts", [{}])[0].get("ip", "")
            )
            print(f"[*] Loaded scan result from {args.from_scan} (target={target})")
        except (FileNotFoundError, json.JSONDecodeError, IndexError) as exc:
            print(f"[!] Could not load scan result: {exc}", file=sys.stderr)
            sys.exit(1)
    elif args.target:
        target      = args.target
        scan_result = _build_mock_scan_result(target)
    else:
        parser.print_help()
        sys.exit(1)

    if not target:
        print("[!] Could not determine target. Use --target.", file=sys.stderr)
        sys.exit(1)

    # ── Run pipeline ──────────────────────────────────────────────────────────
    try:
        run_validation_pipeline(
            scan_result  = scan_result,
            target       = target,
            aggressive   = args.aggressive,
            report_path  = args.report,
        )
    except PermissionError as exc:
        print(f"\n[SCOPE GATE BLOCKED]\n{exc}", file=sys.stderr)
        print("\nRun with --init-scope to create a template scope file.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()