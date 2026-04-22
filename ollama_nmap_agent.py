#!/usr/bin/env python3
"""
Ollama + Nmap agent (production-hardened v4).

Changes from v3:
 - FIX R1 (v3): Profile merging — model flags + operator profile, timing override.
 - FIX R2 (v3): Remote detection logic corrected (not loopback AND not private).
 - FIX R3 (v3): Risk-based port sorting in output.
 - FIX R4 (v3): AI follow-up filtered to open ports only.
 - FIX R5 (v3): Scan timing printed on completion.
 - FIX V1 (v4): --fast restores --min-rate 1000; flag added to ALLOWED_FLAGS.
 - FIX V2 (v4): IPv6 support — socket.getaddrinfo() replaces gethostbyname().
 - FIX V3 (v4): Scan retry on timeout — retries with top-1000 ports automatically.
 - FIX V4 (v4): External intel file — intel.json merged over SERVICE_INTEL at startup.
"""

import argparse
import datetime
import ipaddress
import json
import re
import shlex
import socket
import subprocess
import sys
import time
import importlib
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

_SAFE_TARGET_RE = re.compile(r'^[a-zA-Z0-9.\-:\[\]]{1,253}$')  # FIX V2: allow [] for IPv6

ALLOWED_FLAGS: set[str] = {
    "-sS", "-sT", "-sV", "-sU", "-O", "-A",
    "-Pn", "-n",
    "-T1", "-T2", "-T3", "-T4", "-T5",
    "--open", "--version-light",
    "--min-rate",                        # FIX V1: required for --fast
}

DEFAULT_FLAGS  = "-sS -Pn -T4"
SCAN_TIMEOUT   = 120
MAX_XML_BYTES  = 10 * 1024 * 1024
AUDIT_LOG_PATH = "scan_audit.log"
INTEL_FILE     = "intel.json"           # FIX V4: external intel override path

UDP_SAFE_PORTS = "53,67,68,69,123,137,138,161,162,500,514,520,1194,1900,4500,5353"

RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "unknown": 3}

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
    """
    FIX R1 — merge model flags with a named operator profile.
    Model-supplied timing flags are overridden by the profile's timing token
    so the operator always controls scan aggressiveness.
    """
    base = PROFILES.get(profile, PROFILES["default"])["flags"]
    if not model_flags:
        return base

    # Determine profile timing token (e.g. -T2, -T4)
    profile_timing = next(
        (t for t in base.split() if re.match(r'^-T[0-9]$', t)), None
    )

    try:
        model_tokens = shlex.split(model_flags)
    except ValueError:
        model_tokens = []

    # Strip model timing tokens; they will be replaced by the profile's
    merged = [t for t in model_tokens if not re.match(r'^-T[0-9]$', t)]
    if profile_timing:
        merged.append(profile_timing)

    # De-duplicate while preserving order
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
    "ftp": {
        "risk": "high",
        "notes": "FTP transmits credentials in plaintext and often allows anonymous login.",
        "next_steps": [
            "Test anonymous login",
            "Brute-force credentials",
            "Check for writable directories",
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
}


def _load_external_intel() -> None:
    """
    FIX V4 — merge intel.json (if present) into SERVICE_INTEL at startup.
    Operators can extend or override built-in entries without touching the source.
    """
    try:
        with open(INTEL_FILE) as fh:
            external = json.load(fh)
        if isinstance(external, dict):
            SERVICE_INTEL.update(external)
            print(f"[*] Loaded {len(external)} intel entries from {INTEL_FILE}")
    except FileNotFoundError:
        pass
    except (json.JSONDecodeError, OSError) as exc:
        print(f"[!] Could not load {INTEL_FILE}: {exc}", file=sys.stderr)


# ── Enrichment ────────────────────────────────────────────────────────────────

def enrich_results(scan_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Attach risk/notes/next_steps/cve_hint per port, then sort ports by risk (R3).
    """
    if "hosts" not in scan_result:
        return scan_result

    for host in scan_result["hosts"]:
        for port in host.get("ports", []):
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

        # FIX R3 — sort ports: critical first, then high, medium, unknown
        host["ports"].sort(
            key=lambda p: (
                RISK_ORDER.get(p.get("risk", "unknown"), 3),
                p.get("port", "0").zfill(5),
            )
        )

    return scan_result


def _open_ports_only(scan_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    FIX R4 — strip closed/filtered ports before sending to the AI.
    Returns a shallow copy with only open ports included.
    """
    result = dict(scan_result)
    result["hosts"] = []
    for host in scan_result.get("hosts", []):
        h = dict(host)
        h["ports"] = [p for p in host.get("ports", []) if p.get("state") == "open"]
        result["hosts"].append(h)
    return result


# ── Audit log ─────────────────────────────────────────────────────────────────

def audit_log(target: str, result: Dict[str, Any]) -> None:
    """Append one JSONL entry per scan to scan_audit.log."""
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
    """
    FIX V2 — resolve hostname to IP using getaddrinfo (supports IPv4 + IPv6).
    Returns the first resolved address as a string.
    """
    try:
        results = socket.getaddrinfo(target, None)
        if results:
            return results[0][4][0]
    except socket.gaierror:
        pass
    return None


def _is_remote(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """
    FIX R2 — a host is 'remote' (requires --force) only if it is BOTH
    not loopback AND not private. LAN addresses are allowed by default.
    """
    return not ip.is_loopback and not ip.is_private


def target_allowed(target: str, force: bool = False) -> bool:
    """
    Three-step guard:
      1. Format check  — blocks injection characters.
      2. CIDR check    — single hosts only.
      3. Scope check   — resolves hostname, rejects non-private unless --force.
    """
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


# ── Flag helpers ──────────────────────────────────────────────────────────────

def sanitise_flags(flags: Optional[str]) -> str:
    """
    Whitelist enforced; -T5 clamped to -T4; -sA replaced with -sS.
    FIX V1: --min-rate N is now a two-token flag — handled as a pair.
    """
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

        # FIX V1: --min-rate requires a numeric argument immediately after it
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
    Returns {"timed_out": True} on timeout so the caller can retry (FIX V3).
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
        return {"error": f"nmap output exceeded {MAX_XML_BYTES // (1024*1024)} MB — parse aborted"}

    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(proc.stdout)
        hosts = []
        for host in root.findall("host"):
            addr   = host.find("address")
            ipaddr = addr.get("addr") if addr is not None else None
            hostdict: Dict[str, Any] = {"ip": ipaddr, "ports": []}
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
    """
    2-stage smart scan (discovery → version detection on open ports).
    FIX V3: retries with top-1000 ports on timeout.
    """
    ports = validate_ports(normalise_ports(ports))
    flags = sanitise_flags(flags)

    if "-sU" in flags and ports == "1-65535":
        print(f"[!] UDP full-range scan restricted to common ports: {UDP_SAFE_PORTS}")
        ports = UDP_SAFE_PORTS

    wants_version = "-sV" in flags

    def _build_disc_cmd(p: Optional[str]) -> list[str]:
        try:
            disc_tokens = [f for f in shlex.split(flags) if f != "-sV"] or ["-sS", "-Pn", "-T4"]
        except ValueError:
            disc_tokens = ["-sS", "-Pn", "-T4"]
        cmd = ["nmap", "-oX", "-"] + disc_tokens
        if p:
            cmd += ["-p", p]
        cmd += [target]
        return cmd

    if wants_version:
        cmd1 = _build_disc_cmd(ports)
        print("[*] Stage 1 — port discovery")

        t0 = time.monotonic()
        stage1 = _run_nmap(cmd1)

        # FIX V3: retry on timeout with top-1000 ports
        if stage1.get("timed_out") and retry_on_timeout and ports:
            print("[!] Stage 1 timed out — retrying with top 1000 ports...")
            cmd1_retry = _build_disc_cmd(None)
            stage1 = _run_nmap(cmd1_retry)

        if "error" in stage1:
            return stage1

        open_ports = [
            p["port"]
            for h in stage1.get("hosts", [])
            for p in h.get("ports", [])
            if p.get("state") == "open"
        ]

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
        result = _run_nmap(cmd2)

        # FIX V3: retry stage 2 on timeout
        if result.get("timed_out") and retry_on_timeout:
            print("[!] Stage 2 timed out — using stage 1 results.")
            result = stage1

        elapsed = time.monotonic() - t0
        print(f"[*] Scan completed in {elapsed:.2f}s")  # FIX R5
        return result

    # ── Single-stage scan ──────────────────────────────────────────────────
    t0 = time.monotonic()
    cmd = ["nmap", "-oX", "-"]
    try:
        cmd += shlex.split(flags)
    except ValueError:
        pass
    if ports:
        cmd += ["-p", ports]
    cmd += [target]

    result = _run_nmap(cmd)

    # FIX V3: retry single-stage on timeout
    if result.get("timed_out") and retry_on_timeout and ports:
        print("[!] Scan timed out — retrying with top 1000 ports...")
        cmd_retry = ["nmap", "-oX", "-"]
        try:
            cmd_retry += shlex.split(flags)
        except ValueError:
            pass
        cmd_retry += [target]
        result = _run_nmap(cmd_retry)

    elapsed = time.monotonic() - t0
    print(f"[*] Scan completed in {elapsed:.2f}s")  # FIX R5
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
    """
    FIX R4 — pass only open ports to the model to reduce noise and tokens.
    """
    print("\n[*] Requesting AI follow-up analysis (open ports only)...")
    filtered = _open_ports_only(result)
    try:
        resp = ollama.chat(
            model=model_name,
            messages=[{
                "role": "user",
                "content": (
                    "Given the following network scan result, suggest concrete "
                    "attack paths and prioritised next steps for a penetration tester:\n\n"
                    + json.dumps(filtered, indent=2)
                ),
            }],
        )
        print("\n[AI ANALYSIS]\n" + normalize_ollama_response(resp))
    except Exception as exc:
        print(f"[!] AI follow-up failed: {exc}", file=sys.stderr)


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    _load_external_intel()  # FIX V4: merge external intel before scanning

    parser = argparse.ArgumentParser(description="Ollama-driven Nmap agent (v4).")
    parser.add_argument("--model",       default="dolphin-llama3:8b")
    parser.add_argument("--prompt",      help="Prompt (omit for interactive mode).")
    parser.add_argument("--yes",         action="store_true", help="Auto-confirm scans.")
    parser.add_argument("--force",       action="store_true", help="Allow non-private targets.")
    parser.add_argument("--no-intel",    action="store_true", help="Skip enrichment layer.")
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
        help="FIX V1: append --min-rate 1000 for faster scans.",
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
    ports  = action.get("ports")
    flags  = action.get("flags")

    if not target:
        print("No target from model.")
        sys.exit(1)

    # ── Validate target ───────────────────────────────────────────────────────
    if not target_allowed(target, force=args.force):
        print(f"[!] Refusing to scan '{target}'. Use --force to override.")
        sys.exit(1)

    # FIX R1: merge model flags with operator profile
    flags = apply_profile(flags, args.profile)

    # FIX V1: --fast appends --min-rate 1000
    if args.fast:
        flags = flags + " --min-rate 1000"
        print(f"[*] --fast enabled: appended '--min-rate 1000'. Flags: {flags}")

    # Sanitise after profile + fast merge
    flags = sanitise_flags(flags)

    # ── Confirm ───────────────────────────────────────────────────────────────
    if not args.yes:
        print(f"\nAbout to scan: target={target}  ports={ports}  flags={flags}")
        print("Type 'yes' to continue:")
        if input("> ").strip().lower() not in ("y", "yes"):
            print("Aborted.")
            sys.exit(0)

    # ── Run scan (try llm-tools first, fall back to direct) ───────────────────
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

    # ── Enrich ────────────────────────────────────────────────────────────────
    if not args.no_intel:
        res = enrich_results(res)
        print("\n[*] Enriched result:")
    else:
        print("\n[*] Raw result:")

    print(json.dumps(res, indent=2))

    # ── Audit log ─────────────────────────────────────────────────────────────
    audit_log(target, res)

    # ── AI follow-up ──────────────────────────────────────────────────────────
    if args.ai_followup and "error" not in res:
        ai_followup(res, model_name=args.model)


if __name__ == "__main__":
    main()