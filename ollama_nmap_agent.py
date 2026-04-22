#!/usr/bin/env python3
"""
Ollama + Nmap agent (production-hardened v3).

Security & correctness fixes (v1):
 - Port string normalisation: "all" / "*" → "1-65535".
 - Port string validation: only digits, commas, hyphens allowed (blocks injection).
 - Flag whitelist: only known-safe nmap flags accepted (blocks shell injection).
 - Flag logic: -sA alone or -sA+-sV replaced with -sS/-sS+-sV automatically.
 - Subprocess timeout (default 120 s) prevents indefinite hangs.
 - 2-stage smart scan: fast discovery first, then -sV only on open ports.

Additional hardening (v2):
 - FIX A: Target field injection guard — regex validates target before any use.
 - FIX B: shlex.split wrapped in try/except — malformed model flags no longer crash.
 - FIX C: XML output size ceiling — prevents memory exhaustion on huge nmap output.
 - FIX D: Stage 2 carries forward safe flags (timing, OS, etc.) — not just -sV -Pn.
 - FIX E: UDP full-range guard — -sU + 1-65535 auto-restricted to common UDP ports.
 - FIX F: CIDR target blocked — subnet ranges disabled for safety.
 - FIX G: raw_xml never returned in normal flow — parser error path hardened.

Intelligence & robustness (v3):
 - FIX H: Hostname resolution + private-IP check — hostnames are resolved before
          scope validation instead of trusting the hostname string alone.
 - FIX I: -T5 clamped to -T4 — prevents CPU spike / network flooding.
 - FIX J: Default flags applied when model returns nothing — never runs bare nmap.
 - FIX K: CVE version hints added to enriched port output when version is known.
 - FIX L: Audit log — every enriched result appended to scan_audit.log (JSONL).
 - NEW:   SERVICE_INTEL table + enrich_results() — risk, notes, next_steps per port.
 - NEW:   AI follow-up analysis via Ollama after enrichment (--ai-followup flag).
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
import importlib
from typing import Any, Dict, Iterable, Optional

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

# FIX A: target must be pure IP/hostname chars — no spaces, semicolons, pipes.
_SAFE_TARGET_RE = re.compile(r'^[a-zA-Z0-9.\-:]{1,253}$')

ALLOWED_FLAGS: set[str] = {
    "-sS", "-sT", "-sV", "-sU", "-O", "-A",
    "-Pn", "-n",
    "-T1", "-T2", "-T3", "-T4", "-T5",
    "--open", "--version-light",
}

# FIX J: used when the model returns no flags at all.
DEFAULT_FLAGS = "-sS -Pn -T4"

SCAN_TIMEOUT   = 120
MAX_XML_BYTES  = 10 * 1024 * 1024          # FIX C: 10 MB XML ceiling
AUDIT_LOG_PATH = "scan_audit.log"          # FIX L: append-only JSONL audit file

# FIX E: UDP full-range is unusably slow; restrict to well-known UDP ports.
UDP_SAFE_PORTS = "53,67,68,69,123,137,138,161,162,500,514,520,1194,1900,4500,5353"


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


# ── Enrichment ────────────────────────────────────────────────────────────────

def enrich_results(scan_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Walk every port in the scan result and attach:
      - risk       : critical / high / medium / unknown
      - notes      : human-readable context
      - next_steps : ordered list of follow-up actions
      - cve_hint   : FIX K — search string when version is known
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
                port["next_steps"] = list(intel["next_steps"])  # defensive copy
            elif service:
                port["risk"]       = "unknown"
                port["notes"]      = f"Service '{service}' has no built-in intelligence."
                port["next_steps"] = ["Manual investigation recommended"]
            else:
                port["risk"]       = "unknown"
                port["notes"]      = "Service not identified by nmap."
                port["next_steps"] = []

            # FIX K: lightweight CVE hint when version string is present
            if version and service:
                port["cve_hint"] = f"Search: {service} {version} exploit CVE"

    return scan_result


# ── Audit log ─────────────────────────────────────────────────────────────────

def audit_log(target: str, result: Dict[str, Any]) -> None:
    """FIX L: Append one JSONL entry per scan to scan_audit.log."""
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
    """FIX H: Resolve a hostname to its IP address string."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def target_allowed(target: str, force: bool = False) -> bool:
    """
    Three-step guard:
      1. Format check (FIX A)  — blocks injection characters.
      2. CIDR check   (FIX F)  — single hosts only.
      3. Scope check  (FIX H)  — resolves hostname to IP, then tests private/loopback.
    """
    if not _SAFE_TARGET_RE.match(target):
        print(f"[!] Target '{target}' failed format validation (possible injection).")
        return False

    if "/" in target:
        print("[!] CIDR ranges are disabled. Specify a single host.")
        return False

    if force:
        return True

    # FIX H: resolve before scope check so hostnames are properly evaluated
    resolved = _resolve_to_ip(target)
    if resolved is None:
        print(f"[!] Could not resolve '{target}' — refusing to scan.")
        return False

    try:
        ip = ipaddress.ip_address(resolved)
        allowed = ip.is_loopback or ip.is_private
        if not allowed:
            print(f"[!] '{target}' resolves to {resolved} which is not loopback/private.")
        return allowed
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
    FIX B: Safe shlex split.
    FIX I: -T5 clamped to -T4.
    FIX J: Returns DEFAULT_FLAGS when nothing valid remains.
    Whitelist enforced; -sA replaced with -sS.
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
    for tok in tokens:
        if tok == "-T5":                          # FIX I
            print("[!] -T5 clamped to -T4 to prevent network flooding.")
            safe.append("-T4")
        elif tok in ALLOWED_FLAGS:
            safe.append(tok)
        else:
            print(f"[!] Ignoring unsafe/unknown flag: {tok!r}")

    # Fix -sA: replace with -sS
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

def _run_nmap(cmd: list[str]) -> Dict[str, Any]:
    """
    Execute nmap with -oX - and parse XML output.
    FIX C: 10 MB ceiling on stdout before parsing.
    FIX G: Never returns raw_xml — all errors are clean dicts.
    """
    print("[*] Running:", " ".join(shlex.quote(c) for c in cmd))
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return {"error": f"nmap timed out after {SCAN_TIMEOUT}s"}

    if proc.returncode != 0 and not proc.stdout.strip():
        print("[!] nmap stderr:", proc.stderr.strip(), file=sys.stderr)
        return {"error": proc.stderr.strip() or "nmap returned non-zero exit code"}

    if len(proc.stdout.encode()) > MAX_XML_BYTES:           # FIX C
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
    except ET.ParseError as exc:                             # FIX G
        return {"error": f"XML parse error: {exc}"}
    except Exception as exc:
        return {"error": f"Unexpected parse error: {exc}"}


# ── Main scan logic ───────────────────────────────────────────────────────────

def run_nmap_direct(target: str, ports: Optional[str], flags: Optional[str]) -> Dict[str, Any]:
    """
    2-stage smart scan:
      Stage 1: discovery (no -sV) → find open ports.
      Stage 2: -sV on open ports only, carrying forward all safe flags (FIX D).

    FIX E: -sU + 1-65535 → restricted to common UDP ports.
    """
    ports = validate_ports(normalise_ports(ports))
    flags = sanitise_flags(flags)          # always returns a non-empty string (FIX J)

    # FIX E: UDP + full-range guard
    if "-sU" in flags and ports == "1-65535":
        print(f"[!] UDP full-range scan restricted to common ports: {UDP_SAFE_PORTS}")
        ports = UDP_SAFE_PORTS

    wants_version = "-sV" in flags

    if wants_version:
        # Stage 1: discovery — strip -sV for speed
        try:
            disc_tokens = [f for f in shlex.split(flags) if f != "-sV"] or ["-sS", "-Pn", "-T4"]
        except ValueError:
            disc_tokens = ["-sS", "-Pn", "-T4"]

        cmd1 = ["nmap", "-oX", "-"] + disc_tokens
        if ports:
            cmd1 += ["-p", ports]
        cmd1 += [target]

        print("[*] Stage 1 — port discovery")
        stage1 = _run_nmap(cmd1)
        if "error" in stage1:
            return stage1

        open_ports = [
            p["port"]
            for h in stage1.get("hosts", [])
            for p in h.get("ports", [])
            if p.get("state") == "open"
        ]

        if not open_ports:
            print("[*] No open ports found — skipping version scan.")
            return stage1

        print(f"[*] Stage 2 — version detection on {len(open_ports)} port(s): "
              f"{','.join(open_ports)}")

        # FIX D: carry forward all safe flags, add -sV, force -Pn
        try:
            base = [f for f in shlex.split(flags) if f != "-sV"]
        except ValueError:
            base = ["-sS", "-Pn", "-T4"]

        if "-Pn" not in base:
            base.append("-Pn")

        cmd2 = ["nmap", "-oX", "-"] + base + ["-sV", "-p", ",".join(open_ports), target]
        return _run_nmap(cmd2)

    # Single-stage (no version detection)
    cmd = ["nmap", "-oX", "-"]
    try:
        cmd += shlex.split(flags)
    except ValueError:
        pass
    if ports:
        cmd += ["-p", ports]
    cmd += [target]
    return _run_nmap(cmd)


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
    """Ask the model to suggest attack paths based on enriched scan output."""
    print("\n[*] Requesting AI follow-up analysis...")
    try:
        resp = ollama.chat(
            model=model_name,
            messages=[{
                "role": "user",
                "content": (
                    "Given the following network scan result, suggest concrete "
                    "attack paths and prioritised next steps for a penetration tester:\n\n"
                    + json.dumps(result, indent=2)
                ),
            }],
        )
        print("\n[AI ANALYSIS]\n" + normalize_ollama_response(resp))
    except Exception as exc:
        print(f"[!] AI follow-up failed: {exc}", file=sys.stderr)


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Ollama-driven Nmap agent (v3).")
    parser.add_argument("--model",       default="dolphin-llama3:8b")
    parser.add_argument("--prompt",      help="Prompt (omit for interactive mode).")
    parser.add_argument("--yes",         action="store_true", help="Auto-confirm scans.")
    parser.add_argument("--force",       action="store_true", help="Allow non-private targets.")
    parser.add_argument("--no-intel",    action="store_true", help="Skip enrichment layer.")
    parser.add_argument("--ai-followup", action="store_true",
                        help="Ask the model to analyse enriched results.")
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
