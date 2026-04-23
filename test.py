#!/usr/bin/env python3
"""
Ollama + Nmap agent (production-hardened v11) — integration-corrected.

KEY FIXES vs the original v11:
  1. Guarded import: 'from validation_engine_v1 import ...' is now inside
     a try/except so the scanner works even if the engine file is absent.
  2. Three new argparse flags: --validate, --report PATH, --aggressive.
  3. run_validation_pipeline() wired in as Step 8 in the post-scan pipeline.
  4. audit_log() runs BEFORE validation so the raw scan is always saved.

QUICK START:
  # 1. First-time scope setup (run once)
  python3 validation_engine_v1.py --init-scope
  # edit approved_scope.json → add your target IP and your name

  # 2. Scan only
  python3 nmap_agent_v11.py --prompt "scan 127.0.0.1" --yes

  # 3. Scan + banner grab + fingerprint
  python3 nmap_agent_v11.py --prompt "scan 127.0.0.1" --yes --banner

  # 4. Scan + validate + save report
  python3 nmap_agent_v11.py --prompt "scan 127.0.0.1" --yes --validate --report scan_report

  # 5. Full pipeline (scan + banner + validate + aggressive + report)
  python3 nmap_agent_v11.py --prompt "scan 127.0.0.1" --yes --banner --validate --aggressive --report full_report
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

# ── Validation engine (optional) ─────────────────────────────────────────────
# FIX: was a bare import that crashed startup when the file was absent.
try:
    from validation_engine_v1 import run_validation_pipeline as _run_validation
    _VALIDATION_AVAILABLE = True
except ImportError:
    _VALIDATION_AVAILABLE = False

    def _run_validation(*a, **kw):  # type: ignore[misc]
        raise RuntimeError(
            "validation_engine_v1.py not found.\n"
            "Place it in the same directory as nmap_agent_v11.py."
        )

# ── Ollama ────────────────────────────────────────────────────────────────────
try:
    import ollama
except Exception:
    print("ERROR: 'ollama' python package not installed.", file=sys.stderr)
    print("Install: pip install ollama", file=sys.stderr)
    raise

# ── Optional llm-tools-nmap ───────────────────────────────────────────────────
_llm_tools = None
for _name in ("llm_tools_nmap", "llm-tools-nmap", "llm_tools.nmap", "llm_tools_nmap_py"):
    try:
        _llm_tools = importlib.import_module(_name)
        print(f"[*] Imported llm-tools module: {_name}")
        break
    except Exception:
        _llm_tools = None

# ── Constants ─────────────────────────────────────────────────────────────────
_SAFE_TARGET_RE = re.compile(r'^[a-zA-Z0-9.\-:\[\]]{1,253}$')

ALLOWED_FLAGS: set[str] = {
    "-sS", "-sT", "-sV", "-sU", "-O", "-A",
    "-Pn", "-n",
    "-T1", "-T2", "-T3", "-T4", "-T5",
    "--open", "--version-light",
    "--min-rate",
}

DEFAULT_FLAGS     = "-sS -Pn -T4"
SCAN_TIMEOUT      = 120
MAX_XML_BYTES     = 10 * 1024 * 1024
AUDIT_LOG_PATH    = os.path.expanduser("~/scan_audit.log")
INTEL_FILE        = "intel.json"
FINGERPRINT_CACHE = "fingerprints.json"
CACHE_TTL_HOURS   = 24
BANNER_WORKERS    = 20

UDP_SAFE_PORTS = "53,67,68,69,123,137,138,161,162,500,514,520,1194,1900,4500,5353"
RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4, "none": 5}

# ── Scan profiles ─────────────────────────────────────────────────────────────
PROFILES: Dict[str, Dict[str, Any]] = {
    "stealth":    {"flags": "-sS -Pn -T2", "description": "Low-and-slow SYN scan."},
    "default":    {"flags": "-sS -Pn -T4", "description": "Balanced SYN scan."},
    "aggressive": {"flags": "-sS -sV -O -Pn -T4", "description": "Version + OS detection."},
    "udp":        {"flags": "-sU -Pn -T4", "description": "UDP service discovery."},
}

# ── Target resolution (defined early — used by _scan_timeout) ─────────────────
def _resolve_to_ip(target: str) -> Optional[str]:
    try:
        results = socket.getaddrinfo(target, None)
        if results:
            return results[0][4][0]
    except socket.gaierror:
        pass
    return None


def _is_remote(ip) -> bool:
    return not ip.is_loopback and not ip.is_private


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


# ── Profile merge ─────────────────────────────────────────────────────────────
def apply_profile(model_flags: Optional[str], profile: str) -> str:
    base = PROFILES.get(profile, PROFILES["default"])["flags"]
    if not model_flags:
        return base
    profile_timing = next((t for t in base.split() if re.match(r'^-T[0-9]$', t)), None)
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


# ── Intel table ───────────────────────────────────────────────────────────────
SERVICE_INTEL: Dict[str, Dict[str, Any]] = {
    "ssh":            {"risk":"medium",  "notes":"Remote login. Brute-force target.",
                       "next_steps":["Check weak/default passwords","Enumerate SSH CVEs","Test key-based auth misconfiguration"]},
    "http":           {"risk":"medium",  "notes":"Plain HTTP — unencrypted.",
                       "next_steps":["Directory brute-force (gobuster/ffuf)","Check XSS/SQLi/IDOR","Fingerprint framework"]},
    "https":          {"risk":"medium",  "notes":"Encrypted web. App-layer attacks still apply.",
                       "next_steps":["Check TLS version/cipher (testssl.sh)","Run web vuln scanner","Inspect certificate SANs"]},
    "http-alt":       {"risk":"medium",  "notes":"Alternate HTTP — often dev server or admin panel.",
                       "next_steps":["Identify application","Check admin interfaces","Directory brute-force"]},
    "ftp":            {"risk":"high",    "notes":"Plaintext credentials. Anonymous login common.",
                       "next_steps":["Test anonymous login","Brute-force credentials","Check writable directories"]},
    "rsftp":          {"risk":"medium",  "notes":"Non-standard FTP service.",
                       "next_steps":["Banner-grab to identify service","Test anonymous login"]},
    "smb":            {"risk":"high",    "notes":"Windows file-sharing — frequently misconfigured.",
                       "next_steps":["Enumerate shares (smbclient/CrackMapExec)","Check null sessions","Test EternalBlue (MS17-010)"]},
    "microsoft-ds":   {"risk":"high",    "notes":"SMB over port 445.",
                       "next_steps":["Enumerate shares","Check null sessions","Test EternalBlue (MS17-010)"]},
    "mysql":          {"risk":"high",    "notes":"Database exposed — high-value target.",
                       "next_steps":["Try root with empty password","Enumerate databases","Check UDF privilege escalation"]},
    "postgresql":     {"risk":"high",    "notes":"PostgreSQL — often trust auth misconfiguration.",
                       "next_steps":["Test postgres user blank password","Enumerate databases","Check pg_hba.conf"]},
    "mssql":          {"risk":"high",    "notes":"Microsoft SQL Server exposed.",
                       "next_steps":["Try sa with blank password","Enable xp_cmdshell if creds obtained","Check Metasploit modules"]},
    "rdp":            {"risk":"high",    "notes":"Remote Desktop — especially dangerous without NLA.",
                       "next_steps":["Brute-force credentials","Check BlueKeep (CVE-2019-0708)","Verify NLA is enforced"]},
    "vnc":            {"risk":"high",    "notes":"VNC — commonly no auth or weak password.",
                       "next_steps":["Test unauthenticated access","Brute-force VNC password","Check CVE-2006-2369"]},
    "telnet":         {"risk":"critical","notes":"Cleartext protocol — credentials on the wire.",
                       "next_steps":["Capture credentials via MITM","Try default credentials","Replace with SSH immediately"]},
    "smtp":           {"risk":"medium",  "notes":"Mail agent — relay abuse or user enumeration.",
                       "next_steps":["Test open relay","Enumerate users via VRFY/EXPN","Check software CVEs"]},
    "submission":     {"risk":"medium",  "notes":"SMTP submission port — verify auth enforced.",
                       "next_steps":["Test unauthenticated relay","Check STARTTLS","Enumerate SASL mechanisms"]},
    "imap":           {"risk":"medium",  "notes":"IMAP — plaintext unless STARTTLS enforced.",
                       "next_steps":["Test cleartext auth","Brute-force credentials","Check Dovecot/Cyrus CVEs"]},
    "imaps":          {"risk":"medium",  "notes":"IMAP over TLS.",
                       "next_steps":["Brute-force credentials","Inspect TLS certificate"]},
    "pop3":           {"risk":"medium",  "notes":"POP3 — often cleartext.",
                       "next_steps":["Check STARTTLS","Brute-force credentials"]},
    "pop3s":          {"risk":"medium",  "notes":"POP3 over TLS.",
                       "next_steps":["Brute-force credentials","Inspect TLS certificate"]},
    "dns":            {"risk":"medium",  "notes":"DNS — misconfigured resolvers abused for amplification.",
                       "next_steps":["Test zone transfer (dig axfr)","Check open recursion","Enumerate subdomains"]},
    "snmp":           {"risk":"high",    "notes":"SNMP — default community strings leak host info.",
                       "next_steps":["Try 'public'/'private' community strings","OID walk","Upgrade to SNMPv3"]},
    "ldap":           {"risk":"medium",  "notes":"Directory service — anonymous binds may expose data.",
                       "next_steps":["Test anonymous LDAP bind","Enumerate users/groups","Check cleartext attribute leakage"]},
    "nfs":            {"risk":"high",    "notes":"NFS shares may be world-readable/writable.",
                       "next_steps":["showmount -e target","Mount and inspect shares","Check no_root_squash"]},
    "rsync":          {"risk":"high",    "notes":"rsync daemon — unauthenticated modules expose filesystem.",
                       "next_steps":["rsync target::","Download accessible contents","Check writable modules"]},
    "mongodb":        {"risk":"critical","notes":"MongoDB — no auth exposes all data.",
                       "next_steps":["Test unauthenticated access","Enumerate databases/collections","Check internet-facing exposure"]},
    "redis":          {"risk":"critical","notes":"Redis — often no authentication.",
                       "next_steps":["redis-cli -h target ping","Check CONFIG SET abuse","RCE via cron/authorized_keys"]},
    "upnp":           {"risk":"medium",  "notes":"UPnP — can expose internal topology.",
                       "next_steps":["Enumerate with upnp-inspector","Check CallStranger (CVE-2020-12695)","Disable if not required"]},
    "afs3-fileserver":{"risk":"medium",  "notes":"Andrew File System — rare outside academia.",
                       "next_steps":["Banner-grab (nc target 7000)","Enumerate volumes if confirmed"]},
    "ftp-proxy":      {"risk":"medium",  "notes":"FTP proxy — may forward to internal FTP.",
                       "next_steps":["Identify proxy type","Test unauthenticated access","Check SSRF/bounce-scan"]},
    "ollama":         {"risk":"low",     "notes":"Local Ollama LLM — typically loopback-only.",
                       "next_steps":["Verify bound to 127.0.0.1","Check /api/tags","Ensure no sensitive data in context"]},
    "http-proxy":     {"risk":"medium",  "notes":"HTTP proxy — open proxies enable SSRF.",
                       "next_steps":["Test open proxy (CONNECT)","Check SSRF to internal services"]},
    "socks5":         {"risk":"high",    "notes":"SOCKS5 — unauthenticated allows full TCP tunnelling.",
                       "next_steps":["Test unauthenticated access","Pivot via proxychains"]},
    "cassandra":      {"risk":"high",    "notes":"Cassandra — default installs have no auth.",
                       "next_steps":["cqlsh and list keyspaces","Check default credentials"]},
    "elasticsearch":  {"risk":"critical","notes":"Elasticsearch — historically no auth, all data exposed.",
                       "next_steps":["curl http://target:9200/_cat/indices","Enumerate indices","Check Log4Shell/Groovy RCE"]},
}


def _load_external_intel() -> None:
    try:
        with open(INTEL_FILE) as fh:
            external = json.load(fh)
        if not isinstance(external, dict):
            return
        accepted = 0
        for key, entry in external.items():
            if isinstance(entry, dict) and "risk" in entry and entry["risk"] in RISK_ORDER:
                SERVICE_INTEL[key] = entry
                accepted += 1
        print(f"[*] Loaded {accepted}/{len(external)} valid intel entries from {INTEL_FILE}")
    except FileNotFoundError:
        pass
    except (json.JSONDecodeError, OSError) as exc:
        print(f"[!] Could not load {INTEL_FILE}: {exc}", file=sys.stderr)


# ── Fingerprinting ────────────────────────────────────────────────────────────
FINGERPRINT_RULES: List[Dict[str, Any]] = [
    {"match": ["ssh-"],                                        "service": "ssh",           "match_type": "any"},
    {"match": ["smtp", "esmtp", "postfix", "sendmail", "exim"],"service": "smtp",          "match_type": "any"},
    {"match": ["ftp", "vsftpd", "proftpd"],                   "service": "ftp",           "match_type": "any"},
    {"match": ["http/1.", "http/2", "<html", "content-type:"], "service": "http",          "match_type": "any"},
    {"match": ["server:", "http"],                             "service": "http",          "match_type": "all"},
    {"match": ["mysql", "mariadb"],                            "service": "mysql",         "match_type": "any"},
    {"match": ["redis", "+pong"],                              "service": "redis",         "match_type": "any"},
    {"match": ["mongodb"],                                     "service": "mongodb",       "match_type": "any"},
    {"match": ["cluster_name"],                                "service": "elasticsearch", "match_type": "any"},
    {"match": ["ollama"],                                      "service": "ollama",        "match_type": "any"},
    {"match": ["proxy"],                                       "service": "http-proxy",    "match_type": "any"},
]

_HTTPS_PORTS: frozenset = frozenset({"443", "8443", "4443", "9443"})

PORT_HINTS: Dict[str, str] = {
    "21":"ftp","22":"ssh","23":"telnet","25":"smtp","53":"dns","80":"http",
    "110":"pop3","143":"imap","443":"https","445":"microsoft-ds","587":"submission",
    "993":"imaps","995":"pop3s","1433":"mssql","3306":"mysql","3389":"rdp",
    "5432":"postgresql","5900":"vnc","6379":"redis","8080":"http-alt","8443":"https",
    "9200":"elasticsearch","11211":"memcached","11434":"ollama","27017":"mongodb",
    "389":"ldap","636":"ldaps","1521":"oracle","2049":"nfs","2082":"cpanel",
    "2083":"cpanel-ssl","2181":"zookeeper","2375":"docker","2376":"docker-ssl",
    "3000":"http-alt","4000":"http-alt","5000":"http-alt","5601":"kibana",
    "5985":"winrm","5986":"winrm-ssl","6667":"irc","7001":"weblogic",
    "7474":"neo4j","7687":"neo4j-bolt","8000":"http-alt","8008":"http-alt",
    "8081":"http-alt","8088":"http-alt","8888":"http-alt","9000":"sonarqube",
    "9042":"cassandra","9092":"kafka","9090":"http-alt","10000":"webmin",
}


def _attempt_tls_probe(host: str, port_num: str) -> Optional[str]:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        with socket.create_connection((host, int(port_num or 0)), timeout=2.0) as raw:
            with ctx.wrap_socket(raw) as tls:
                cert = tls.getpeercert(binary_form=False) or {}
                cn   = (cert.get("subject") or ((("",),),))[0][0][1]
        return f"TLS OK (CN={cn})" if cn else "TLS OK"
    except Exception:
        return None


def fingerprint_service(port: Dict[str, Any]) -> Dict[str, Any]:
    current_service = port.get("service")
    current_version = port.get("version")
    port_num        = str(port.get("port", ""))
    host            = port.get("_host", "")

    if current_service and current_service not in ("unknown", None) and current_version:
        port.setdefault("confidence", "nmap")
        return port

    banner     = (port.get("banner") or "").lower()
    banner_raw = port.get("banner") or ""

    def _set(service: str, confidence: str, fingerprint: str) -> None:
        if service == "http" and port_num in _HTTPS_PORTS:
            service = "https"
        port["service"]     = service
        port["confidence"]  = confidence
        port["fingerprint"] = fingerprint
        if not current_version and banner_raw:
            port["version"] = banner_raw[:80].strip()
        print(f"    [fp] {port_num} → {service} ({confidence})")

    if banner:
        for rule in FINGERPRINT_RULES:
            mtype = rule.get("match_type", "any")
            matched = (all if mtype == "all" else any)(sig in banner for sig in rule["match"])
            if matched and (not current_service or current_service in ("unknown", None)):
                _set(rule["service"], "banner-match", str(rule["match"]))
                if port.get("service") == "http" and port_num not in _HTTPS_PORTS and host:
                    tls = _attempt_tls_probe(host, port_num)
                    if tls:
                        _set("https", "tls-probe", tls)
                return port

    if not current_service or current_service in ("unknown", None):
        if host:
            tls = _attempt_tls_probe(host, port_num)
            if tls:
                _set("https", "tls-probe", tls)
                return port

    if port_num in PORT_HINTS and (not current_service or current_service in ("unknown", None)):
        _set(PORT_HINTS[port_num], "port-heuristic", f"port {port_num}")

    return port


def _load_fingerprint_cache() -> Dict[str, Any]:
    try:
        with open(FINGERPRINT_CACHE) as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return {}
        cutoff  = time.time() - CACHE_TTL_HOURS * 3600
        evicted = 0
        fresh   = {}
        for key, entry in data.items():
            if entry.get("_ts", 0) >= cutoff:
                fresh[key] = entry
            else:
                evicted += 1
        if evicted:
            print(f"[*] Fingerprint cache: evicted {evicted} stale entries")
        return fresh
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_fingerprint_cache(cache: Dict[str, Any]) -> None:
    try:
        with open(FINGERPRINT_CACHE, "w") as fh:
            json.dump(cache, fh, indent=2)
    except OSError as exc:
        print(f"[!] Could not write fingerprint cache: {exc}", file=sys.stderr)


def apply_fingerprinting(scan_result: Dict[str, Any]) -> Dict[str, Any]:
    cache      = _load_fingerprint_cache()
    changed    = False
    work_items: List[tuple] = []

    for host in scan_result.get("hosts", []):
        ip = host.get("ip", "")
        for port in host.get("ports", []):
            if port.get("state") != "open":
                continue
            port["_host"] = ip
            ck = f"{ip}:{port.get('port')}"
            if ck in cache:
                cached = cache[ck]
                if not port.get("service") or port["service"] in ("unknown", None):
                    for f in ("service", "confidence", "fingerprint", "version"):
                        if f in cached:
                            port[f] = cached[f]
                    print(f"    [fp] port {port.get('port')} → {port.get('service')} (cache)")
                continue
            work_items.append((ip, port))

    if work_items:
        print(f"[*] Fingerprinting {len(work_items)} port(s) (workers={BANNER_WORKERS})...")
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
                        ck    = f"{_ip}:{_port.get('port')}"
                        entry = {k: _port[k] for k in ("service","confidence","fingerprint","version") if k in _port}
                        entry["_ts"] = time.time()
                        cache[ck] = entry
                        changed   = True
                except Exception as exc:
                    print(f"[!] Fingerprint task failed: {exc}", file=sys.stderr)

    if changed:
        _save_fingerprint_cache(cache)
    return scan_result


# ── OS correlation ────────────────────────────────────────────────────────────
_WINDOWS_ESCALATE: Dict[str, Dict[str, Any]] = {
    "smb":          {"risk":"critical","os_note":"Windows confirmed — SMB primary attack vector.",
                     "prepend_steps":["crackmapexec smb target --gen-relay-list"]},
    "microsoft-ds": {"risk":"critical","os_note":"Windows confirmed — SMB/445 highest priority.",
                     "prepend_steps":["crackmapexec smb target","Test MS17-010 immediately"]},
    "rdp":          {"risk":"critical","os_note":"Windows confirmed — RDP primary remote access.",
                     "prepend_steps":["nmap -p 3389 --script rdp-enum-encryption target",
                                      "msfconsole → auxiliary/scanner/rdp/cve_2019_0708_bluekeep"]},
}


def apply_os_correlation(scan_result: Dict[str, Any]) -> Dict[str, Any]:
    for host in scan_result.get("hosts", []):
        if "windows" not in (host.get("os") or "").lower():
            continue
        print(f"[*] OS correlation: Windows on {host.get('ip')} — escalating SMB/RDP.")
        for port in host.get("ports", []):
            if port.get("state") != "open":
                continue
            service = (port.get("service") or "").lower()
            if service in _WINDOWS_ESCALATE:
                esc = _WINDOWS_ESCALATE[service]
                port["risk"]       = esc["risk"]
                port["os_note"]    = esc["os_note"]
                port["next_steps"] = esc["prepend_steps"] + port.get("next_steps", [])
    return scan_result


# ── Exploit chaining ──────────────────────────────────────────────────────────
_CHAIN_PIVOTS: Dict[tuple, str] = {
    ("ftp","ssh"):           "FTP creds often reused → try on SSH",
    ("ftp","smb"):           "FTP write access → plant payload for SMB pickup",
    ("http","mysql"):        "Web app may expose DB creds in config files",
    ("http","redis"):        "SSRF via web app → hit Redis on loopback",
    ("https","mysql"):       "Web app may expose DB creds in config files",
    ("https","redis"):       "SSRF via web app → hit Redis on loopback",
    ("smtp","ssh"):          "SMTP user enum reveals valid usernames → SSH brute",
    ("ssh","mysql"):         "SSH access → read /etc/mysql or .my.cnf",
    ("ssh","redis"):         "SSH access → write authorized_keys via Redis CONFIG SET",
    ("mysql","ssh"):         "MySQL UDF → OS command → SSH persistence",
    ("postgresql","ssh"):    "PostgreSQL COPY TO/FROM PROGRAM → OS command",
    ("redis","ssh"):         "Redis CONFIG SET → write authorized_keys",
    ("mongodb","ssh"):       "MongoDB data may contain SSH keys",
    ("elasticsearch","ssh"): "Groovy RCE → shell → SSH persistence",
    ("smb","rdp"):           "SMB credential dump → reuse on RDP",
    ("rdp","smb"):           "RDP session → access SMB shares directly",
    ("snmp","ssh"):          "SNMP OID walk may leak SSH creds",
    ("ldap","smb"):          "LDAP user enum → targeted SMB attacks",
    ("ldap","rdp"):          "LDAP user enum → targeted RDP brute-force",
    ("vnc","ssh"):           "VNC screen access → harvest SSH keys",
    ("http-proxy","redis"):  "Open proxy → SSRF into internal Redis",
    ("socks5","mysql"):      "Unauthenticated SOCKS5 → tunnel into MySQL",
    ("socks5","postgresql"): "Unauthenticated SOCKS5 → tunnel into PostgreSQL",
}


def build_exploit_chain(scan_result: Dict[str, Any]) -> Dict[str, Any]:
    for host in scan_result.get("hosts", []):
        open_ports = [p for p in host.get("ports", []) if p.get("state") == "open"]
        if not open_ports:
            continue
        sorted_ports = sorted(
            open_ports,
            key=lambda p: (RISK_ORDER.get(p.get("risk","unknown"), 4),
                           str(p.get("port","")).zfill(5)),
        )
        services = [(p.get("service") or "").lower().strip()
                    for p in sorted_ports if (p.get("service") or "").strip()]
        chain: List[Dict[str, Any]] = []
        step = 1
        for i, svc_a in enumerate(services):
            for svc_b in services[i+1:]:
                pivot = _CHAIN_PIVOTS.get((svc_a, svc_b))
                if pivot:
                    chain.append({"step": step, "from": svc_a, "to": svc_b, "pivot": pivot})
                    step += 1
        if chain:
            host["chain_of_attack"] = chain
            print(f"\n[EXPLOIT CHAIN] {host.get('ip')} — {len(chain)} pivot(s):")
            for link in chain:
                print(f"  Step {link['step']:2d}: {link['from']} → {link['to']}")
                print(f"            {link['pivot']}")
        else:
            print(f"\n[EXPLOIT CHAIN] {host.get('ip')} — no known pivot combinations.")
    return scan_result


# ── Enrichment ────────────────────────────────────────────────────────────────
def enrich_results(scan_result: Dict[str, Any]) -> Dict[str, Any]:
    if "hosts" not in scan_result:
        return scan_result
    for host in scan_result["hosts"]:
        for port in host.get("ports", []):
            if port.get("state") != "open":
                port["risk"]       = "none"
                port["notes"]      = f"Not accessible (state: {port.get('state','unknown')})."
                port["next_steps"] = []
                continue
            service = (port.get("service") or "").lower().strip()
            version = port.get("version")
            intel   = SERVICE_INTEL.get(service) if service else None
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
            key=lambda p: (RISK_ORDER.get(p.get("risk","unknown"), 4),
                           p.get("port","0").zfill(5))
        )
    return scan_result


# ── Banner grabbing ───────────────────────────────────────────────────────────
_BANNER_TIMEOUTS: Dict[int, float] = {
    25:4.0, 110:3.5, 143:3.5, 587:4.0, 3306:3.0,
    5432:3.0, 6379:2.5, 27017:3.0, 9200:3.0,
}
_BANNER_PROBES: Dict[int, bytes] = {
    22:b"", 6379:b"PING\r\n", 3306:b"", 5432:b"",
    27017:b"", 9200:b"GET / HTTP/1.0\r\n\r\n",
}
_HTTP_PROBE = b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n"


def banner_grab(host: str, port: int, timeout: Optional[float] = None) -> Optional[str]:
    t = timeout if timeout is not None else _BANNER_TIMEOUTS.get(port, 2.0)
    probe = _BANNER_PROBES.get(port, _HTTP_PROBE)
    try:
        with socket.create_connection((host, port), timeout=t) as s:
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
    port["_host"] = ip_str
    if port.get("service") and port["service"] not in ("unknown", None) and port.get("version"):
        return
    if port.get("banner"):
        return
    port_num = port.get("port")
    if not port_num:
        return
    print(f"[*] Banner grab: {ip_str}:{port_num}")
    b = banner_grab(ip_str, int(port_num))
    if b:
        port["banner"] = b
        print(f"    → {b[:80]!r}")
    else:
        print(f"    → no banner")


def banner_grab_scan(scan_result: Dict[str, Any]) -> Dict[str, Any]:
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
            if port.get("state") == "open":
                tasks.append((ip_str, port))
    if tasks:
        print(f"[*] Banner grabbing {len(tasks)} port(s) (workers={BANNER_WORKERS})...")
        with ThreadPoolExecutor(max_workers=BANNER_WORKERS) as ex:
            futures = [ex.submit(_grab_one_port, ip, p) for ip, p in tasks]
            for f in as_completed(futures):
                try:
                    f.result()
                except Exception as exc:
                    print(f"[!] Banner grab failed: {exc}", file=sys.stderr)
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
            by_risk.setdefault(p.get("risk","unknown"), []).append(
                f"{p['port']}/{p.get('service','?')}")
        print(f"\n[EXPOSURE SUMMARY] {host.get('ip')} — {len(open_ports)} open port(s)")
        for level in ("critical","high","medium","low","unknown"):
            if level in by_risk:
                print(f"  {level.upper():8s}  {', '.join(by_risk[level])}")


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
def target_allowed(target: str, force: bool = False) -> bool:
    if not _SAFE_TARGET_RE.match(target):
        print(f"[!] Target '{target}' failed format validation.")
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
            print(f"[!] '{target}' resolves to {resolved} (not loopback/private). Use --force.")
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
    return "1-65535" if s in ("all","all ports","*","0-65535") else ports


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
        print(f"[*] Prompt override: top {n} ports → --top-ports {n}.")
        return f"__top_{n}__"
    print(f"[*] Prompt override: top {n} ports → nmap default top-1000.")
    return None


# ── Flag helpers ──────────────────────────────────────────────────────────────
def sanitise_flags(flags: Optional[str]) -> str:
    if not flags:
        return DEFAULT_FLAGS
    try:
        tokens = shlex.split(flags)
    except ValueError as exc:
        print(f"[!] Malformed flags ({exc}) — using defaults.")
        return DEFAULT_FLAGS
    safe: list[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok == "--min-rate":
            if i+1 < len(tokens) and re.fullmatch(r'\d+', tokens[i+1]):
                safe.extend(["--min-rate", tokens[i+1]])
                i += 2
            else:
                print("[!] --min-rate requires a numeric argument — skipping.")
                i += 1
            continue
        if tok == "-T5":
            print("[!] -T5 clamped to -T4.")
            safe.append("-T4")
        elif tok in ALLOWED_FLAGS:
            safe.append(tok)
        else:
            print(f"[!] Ignoring unsafe flag: {tok!r}")
        i += 1
    if "-sA" in safe:
        safe = ["-sS" if f == "-sA" else f for f in safe]
    return " ".join(safe) if safe else DEFAULT_FLAGS


# ── Nmap runner ───────────────────────────────────────────────────────────────
def _run_nmap(cmd: list[str], timeout: int = SCAN_TIMEOUT) -> Dict[str, Any]:
    print("[*] Running:", " ".join(shlex.quote(c) for c in cmd))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"timed_out": True, "error": f"nmap timed out after {timeout}s"}
    if proc.returncode != 0 and not proc.stdout.strip():
        return {"error": proc.stderr.strip() or "nmap returned non-zero exit code"}
    if len(proc.stdout.encode()) > MAX_XML_BYTES:
        return {"error": "nmap output too large"}
    try:
        import xml.etree.ElementTree as ET
        root  = ET.fromstring(proc.stdout)
        hosts = []
        for host in root.findall("host"):
            addr    = host.find("address")
            ipaddr  = addr.get("addr") if addr is not None else None
            hd: Dict[str, Any] = {"ip": ipaddr, "ports": []}
            os_el = host.find("os")
            if os_el is not None:
                matches = os_el.findall("osmatch")
                if matches:
                    hd["os"] = matches[0].get("name", "")
            ports_el = host.find("ports")
            if ports_el is None:
                hosts.append(hd)
                continue
            for p in ports_el.findall("port"):
                se = p.find("state")
                sv = p.find("service")
                hd["ports"].append({
                    "port":     p.get("portid"),
                    "protocol": p.get("protocol"),
                    "state":    se.get("state")  if se is not None else None,
                    "service":  sv.get("name")   if sv is not None else None,
                    "version":  (sv.get("version") or sv.get("product") or None)
                                if sv is not None else None,
                })
            hosts.append(hd)
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
        print(f"[*] Using --top-ports {n}.")

    ports = validate_ports(normalise_ports(ports))
    flags = sanitise_flags(flags)

    if "-sU" in flags and ports == "1-65535":
        print(f"[!] UDP full-range → common ports: {UDP_SAFE_PORTS}")
        ports = UDP_SAFE_PORTS

    wants_version = "-sV" in flags

    def _build(p, top_n=None):
        try:
            dt = [f for f in shlex.split(flags) if f != "-sV"] or ["-sS","-Pn","-T4"]
        except ValueError:
            dt = ["-sS","-Pn","-T4"]
        cmd = ["nmap","-oX","-"] + dt
        if top_n:   cmd += ["--top-ports", top_n]
        elif p:     cmd += ["-p", p]
        cmd += [target]
        return cmd

    to = _scan_timeout(target)

    if wants_version:
        t0     = time.monotonic()
        stage1 = _run_nmap(_build(ports, top_n=top_ports_flag), timeout=to)
        print("[*] Stage 1 — port discovery")
        if stage1.get("timed_out") and retry_on_timeout and (ports or top_ports_flag):
            print("[!] Stage 1 timed out — retrying with top 1000 ports...")
            stage1 = _run_nmap(_build(None), timeout=to)
        if "error" in stage1:
            return stage1
        open_ports = list(dict.fromkeys(
            p["port"] for h in stage1.get("hosts",[])
            for p in h.get("ports",[]) if p.get("state") == "open"
        ))
        if not open_ports:
            print(f"[*] No open ports. ({time.monotonic()-t0:.2f}s)")
            return stage1
        print(f"[*] Stage 2 — version detection on {len(open_ports)} port(s): {','.join(open_ports)}")
        try:
            base = [f for f in shlex.split(flags) if f != "-sV"]
        except ValueError:
            base = ["-sS","-Pn","-T4"]
        if "-Pn" not in base:
            base.append("-Pn")
        cmd2   = ["nmap","-oX","-"] + base + ["-sV","-p",",".join(open_ports), target]
        result = _run_nmap(cmd2, timeout=to)
        if result.get("timed_out") and retry_on_timeout:
            print("[!] Stage 2 timed out — retrying with --version-light...")
            cmd2l  = ["nmap","-oX","-"] + base + ["-sV","--version-light","-p",",".join(open_ports), target]
            result = _run_nmap(cmd2l, timeout=to)
            if result.get("timed_out"):
                print("[!] --version-light also timed out — using stage 1 results.")
                result = stage1
        print(f"[*] Scan completed in {time.monotonic()-t0:.2f}s")
        return result

    t0  = time.monotonic()
    cmd = ["nmap","-oX","-"]
    try:
        cmd += shlex.split(flags)
    except ValueError:
        pass
    if top_ports_flag:  cmd += ["--top-ports", top_ports_flag]
    elif ports:         cmd += ["-p", ports]
    cmd += [target]
    result = _run_nmap(cmd, timeout=to)
    if result.get("timed_out") and retry_on_timeout and (ports or top_ports_flag):
        print("[!] Scan timed out — retrying with top 1000 ports...")
        cr = ["nmap","-oX","-"]
        try:
            cr += shlex.split(flags)
        except ValueError:
            pass
        cr    += [target]
        result = _run_nmap(cr, timeout=to)
    print(f"[*] Scan completed in {time.monotonic()-t0:.2f}s")
    return result


# ── llm-tools-nmap ────────────────────────────────────────────────────────────
def run_llm_tools_nmap(target: str, ports: Optional[str], flags: Optional[str]):
    if _llm_tools is None:
        raise ImportError("llm-tools-nmap not importable")
    last_exc: Optional[Exception] = None
    for fname in ("run_scan","nmap_scan","scan","do_scan"):
        if hasattr(_llm_tools, fname):
            fn = getattr(_llm_tools, fname)
            try:
                return fn(target=target, ports=ports, flags=flags)
            except TypeError:
                try:
                    return fn(target, ports, flags)
                except Exception as exc:
                    last_exc = exc
    raise RuntimeError(f"llm-tools-nmap: no working entrypoint. Last: {last_exc}")


# ── LLM helpers ───────────────────────────────────────────────────────────────
SYSTEM_INSTRUCTION = """
You are an assistant that must produce JSON ONLY (no extra text) describing a single action.
Valid actions:
  1) {"action":"scan","target":"<ip_or_hostname>","ports":"22,80","flags":"-sS -Pn -T4"}
  2) {"action":"explain","text":"..."}
  3) {"action":"question","text":"<your question>"}
Rules: target = single IP/hostname. ports = numeric ranges only. Never use "all" for ports.
flags: use -sS not -sA, add -sV only when explicitly requested, never -T5.
"""


def normalize_ollama_response(resp: Any) -> str:
    if isinstance(resp, Iterable) and not isinstance(resp, (str, bytes, dict, list)):
        try:
            parts = []
            for chunk in resp:
                if isinstance(chunk, dict):
                    if "message" in chunk and isinstance(chunk["message"], dict) and "content" in chunk["message"]:
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
        return "\n".join(normalize_ollama_response(i) if isinstance(i, dict) else str(i) for i in resp)
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
                return text[start:i+1]
    return None


def ask_model_for_action(user_prompt: str, model_name: str) -> Dict[str, Any]:
    messages  = [{"role":"system","content":SYSTEM_INSTRUCTION},
                 {"role":"user",  "content":user_prompt}]
    resp      = ollama.chat(model=model_name, messages=messages)
    text      = normalize_ollama_response(resp)
    json_text = extract_first_json(text)
    if not json_text:
        raise ValueError(f"Model did not return JSON.\nRaw:\n{text}")
    try:
        return json.loads(json_text)
    except Exception as exc:
        try:
            return json.loads(json_text.replace("'", '"'))
        except Exception:
            raise ValueError(f"Could not parse model JSON.\n{json_text}\n{exc}")


def ai_followup(result: Dict[str, Any], model_name: str) -> None:
    print("\n[*] Requesting AI follow-up analysis (open ports only)...")
    filtered = _open_ports_only(result)
    try:
        resp = ollama.chat(model=model_name, messages=[{
            "role": "user",
            "content": (
                "Given the following network scan result (including any exploit chain), "
                "suggest concrete attack paths and prioritised next steps:\n\n"
                + json.dumps(filtered, indent=2)
            ),
        }])
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
    parser.add_argument("--banner",      action="store_true", help="Banner-grab open ports.")
    parser.add_argument("--ai-followup", action="store_true", help="AI analysis after scan.")

    # ── Validation engine flags ───────────────────────────────────────────────
    parser.add_argument(
        "--validate",
        action="store_true",
        help=(
            "Run validation engine after scan. "
            "Requires approved_scope.json — run: "
            "python3 validation_engine_v1.py --init-scope"
        ),
    )
    parser.add_argument(
        "--report",
        metavar="PATH",
        help="Save JSON + HTML report to PATH (used with --validate). No extension needed.",
    )
    parser.add_argument(
        "--aggressive",
        action="store_true",
        help="Probe sensitive services in validation (SNMP, LDAP, RDP, MSSQL).",
    )
    # ─────────────────────────────────────────────────────────────────────────

    parser.add_argument("--profile", choices=list(PROFILES), default="default")
    parser.add_argument("--fast",    action="store_true", help="Append --min-rate 1000.")
    args = parser.parse_args()

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

    try:
        action = ask_model_for_action(user_prompt, model_name=args.model)
    except Exception as exc:
        print("ERROR:", exc, file=sys.stderr)
        sys.exit(1)

    print("[*] Model action:", action)

    if action.get("action") == "question":
        print("[MODEL QUESTION]", action.get("text")); sys.exit(0)
    if action.get("action") == "explain":
        print("[MODEL EXPLANATION]\n", action.get("text")); sys.exit(0)
    if action.get("action") != "scan":
        print("Unknown action:", action.get("action")); sys.exit(1)

    target = (action.get("target") or "").strip()
    flags  = action.get("flags")
    ports  = action.get("ports") if prompt_port_override == "NONE" else prompt_port_override

    if not target:
        print("No target from model."); sys.exit(1)

    if not target_allowed(target, force=args.force):
        print(f"[!] Refusing to scan '{target}'. Use --force to override."); sys.exit(1)

    flags = apply_profile(flags, args.profile)
    if args.fast:
        flags = flags + " --min-rate 1000"
    flags = sanitise_flags(flags)

    if not args.yes:
        print(f"\nAbout to scan: target={target}  ports={ports}  flags={flags}")
        print("Type 'yes' to continue:")
        if input("> ").strip().lower() not in ("y","yes"):
            print("Aborted."); sys.exit(0)

    if _llm_tools is not None:
        try:
            print("[*] Trying llm-tools-nmap integration...")
            res = run_llm_tools_nmap(target=target, ports=ports, flags=flags)
            print(json.dumps(res, indent=2)); sys.exit(0)
        except Exception as exc:
            print(f"[!] llm-tools-nmap failed: {exc} — falling back.", file=sys.stderr)

    res = run_nmap_direct(target=target, ports=ports, flags=flags)

    # ── Post-scan pipeline ────────────────────────────────────────────────────
    if not args.no_intel:
        res = enrich_results(res)                               # Step 1

        if args.banner and "error" not in res:
            print("\n[*] Banner grabbing...")
            res = banner_grab_scan(res)                         # Step 2
            print("\n[*] Fingerprinting...")
            res = apply_fingerprinting(res)                     # Step 3
            print("\n[*] Re-enriching after fingerprinting...")
            res = enrich_results(res)                           # Step 4

        print("\n[*] OS correlation...")
        res = apply_os_correlation(res)                         # Step 5
        print("\n[*] Building exploit chain...")
        res = build_exploit_chain(res)                          # Step 6
        print_exposure_summary(res)                             # Step 7
        print("\n[*] Enriched result:")
    else:
        if args.banner and "error" not in res:
            res = banner_grab_scan(res)
            res = apply_fingerprinting(res)
        print("\n[*] Raw result:")

    print(json.dumps(res, indent=2))

    audit_log(target, res)                                      # always before validation

    # ── Step 8: Validation engine ─────────────────────────────────────────────
    if args.validate and "error" not in res:
        if not _VALIDATION_AVAILABLE:
            print(
                "\n[!] --validate requested but validation_engine_v1.py was not found.\n"
                "    Copy validation_engine_v1.py into the same directory as this script.",
                file=sys.stderr,
            )
        else:
            print("\n[*] Running validation engine (Step 8)...")
            print("[*] (Requires approved_scope.json — run --init-scope if needed)")
            try:
                res = _run_validation(
                    scan_result  = res,
                    target       = target,
                    aggressive   = args.aggressive,
                    report_path  = args.report,
                )
            except PermissionError as exc:
                print(f"\n[SCOPE GATE BLOCKED]\n{exc}", file=sys.stderr)
                print(
                    "\nTo fix:\n"
                    "  python3 validation_engine_v1.py --init-scope\n"
                    "  # then edit approved_scope.json:\n"
                    f'  # add "{target}" to the "targets" list\n'
                    "  # set your name in 'approved_by'",
                    file=sys.stderr,
                )

    if args.ai_followup and "error" not in res:
        ai_followup(res, model_name=args.model)


if __name__ == "__main__":
    main()