#!/usr/bin/env python3
"""
Ollama + Nmap agent (service-version aware, robust fallback).

Changes:
 - Ensures '-sV' and '--script=mysql-info' are automatically added.
 - Detects when llm-tools-nmap output lacks version info and reruns nmap locally.
 - Avoids premature sys.exit() before fallback.
"""

import argparse, json, re, shlex, subprocess, sys, inspect, ipaddress, importlib
from typing import Optional, Dict, Any, Iterable

# Try to import ollama
try:
    import ollama
except Exception:
    print("ERROR: 'ollama' package not installed. Install using: pip install ollama", file=sys.stderr)
    raise

# Try to import llm-tools-nmap (optional)
_llm_tools = None
for name in ("llm_tools_nmap", "llm-tools-nmap", "llm_tools.nmap", "llm_tools_nmap_py"):
    try:
        _llm_tools = importlib.import_module(name)
        print(f"[*] Imported llm-tools module: {name}")
        break
    except Exception:
        pass

# ---------- UTILITIES ----------

def target_allowed(target: str) -> bool:
    try:
        ip = ipaddress.ip_address(target)
        return ip.is_loopback or ip.is_private
    except Exception:
        return target.lower() in ("localhost", "127.0.0.1", "::1")

def run_nmap_direct(target: str, ports: Optional[str], flags: Optional[str]) -> Dict[str, Any]:
    cmd = ["nmap", "-oX", "-"]
    if flags:
        cmd += shlex.split(flags)
    if ports:
        cmd += ["-p", ports]
    cmd.append(target)
    print("[*] Running direct nmap:", " ".join(cmd))
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if not proc.stdout.strip():
        return {"error": proc.stderr.strip()}

    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(proc.stdout)
        hosts = []
        for host in root.findall("host"):
            addr = host.find("address")
            ipaddr = addr.get("addr") if addr is not None else None
            hostdict = {"ip": ipaddr, "ports": []}
            for p in host.findall(".//port"):
                portnum = p.get("portid")
                proto = p.get("protocol")
                state = p.findtext("state[@state]")
                svc_el = p.find("service")
                service = svc_el.get("name") if svc_el is not None else None
                version = svc_el.get("version") if svc_el is not None else None
                product = svc_el.get("product") if svc_el is not None else None
                hostdict["ports"].append({
                    "port": portnum,
                    "protocol": proto,
                    "state": state,
                    "service": service,
                    "product": product,
                    "version": version
                })
            hosts.append(hostdict)
        return {"hosts": hosts}
    except Exception as e:
        return {"error": str(e), "raw_xml": proc.stdout}

def run_llm_tools_nmap(target: str, ports: Optional[str], flags: Optional[str]):
    if _llm_tools is None:
        raise ImportError("llm-tools-nmap not found")

    for fn_name in ("run_scan", "nmap_scan", "scan", "do_scan"):
        if hasattr(_llm_tools, fn_name):
            fn = getattr(_llm_tools, fn_name)
            try:
                return fn(target, ports, flags)
            except TypeError:
                try:
                    return fn(target, ports)
                except TypeError:
                    return fn(target)
    raise RuntimeError("llm-tools-nmap found, but no callable method worked")

SYSTEM_INSTRUCTION = """
You are an assistant that must produce JSON ONLY describing a single action.
Valid actions:
  {"action":"scan","target":"<ip>","ports":"22,80","flags":"-sS -Pn"}
"""

def normalize_ollama_response(resp):
    if isinstance(resp, dict):
        return resp.get("message", {}).get("content", "")
    return str(resp)

def extract_first_json(text: str) -> Optional[str]:
    start, depth = None, 0
    for i, ch in enumerate(text):
        if ch == "{":
            if start is None:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                return text[start:i+1]
    return None

def ask_model_for_action(user_prompt: str, model_name: str) -> Dict[str, Any]:
    resp = ollama.chat(model=model_name, messages=[
        {"role": "system", "content": SYSTEM_INSTRUCTION},
        {"role": "user", "content": user_prompt}
    ])
    txt = normalize_ollama_response(resp)
    jtxt = extract_first_json(txt)

    if not jtxt:
        # Try to guess a JSON-like string
        jtxt = txt.strip()
    
    # Replace single quotes with double quotes
    jtxt = jtxt.replace("'", '"')

    # Remove trailing commas
    jtxt = re.sub(r',\s*}', '}', jtxt)
    jtxt = re.sub(r',\s*]', ']', jtxt)

    try:
        return json.loads(jtxt)
    except json.JSONDecodeError as e:
        print("ERROR parsing JSON from model:", e)
        print("Raw text:", txt)
        return {}

def user_requested_version(user_prompt: str, action: Dict[str, Any]) -> bool:
    up = (user_prompt or "").lower()
    fl = (action.get("flags") or "").lower()
    return any(k in up for k in ("version", "service version")) or "-sv" in fl or "-a" in fl

# ---------- MAIN ----------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="dolphin-llama3:8b")
    parser.add_argument("--prompt")
    parser.add_argument("--yes", action="store_true")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    user_prompt = args.prompt or input("> ").strip()
    action = ask_model_for_action(user_prompt, args.model)
    print("[*] Model action:", action)

    if action.get("action") != "scan":
        print("Model returned non-scan action.")
        return

    target, ports, flags = action.get("target"), action.get("ports"), action.get("flags", "")
    if user_requested_version(user_prompt, action):
        if "-sV" not in flags:
            flags += " -sV"
            print("[*] Added '-sV'")
        if "3306" in (ports or ""):
            flags += " --script=mysql-info"
            print("[*] Added '--script=mysql-info'")

    if not args.force and not target_allowed(target):
        print(f"[!] Refusing external scan: {target}")
        return

    if _llm_tools:
        try:
            print("[*] Trying llm-tools-nmap integration...")
            result = run_llm_tools_nmap(target, ports, flags)
            if isinstance(result, str):
                print("[*] llm-tools-nmap result:\n", result)
                # If no version info detected, run fallback
                if "version" not in result.lower() and "mysql" in result.lower():
                    print("[*] No version info found, running local fallback with -sV ...")
                    parsed = run_nmap_direct(target, ports, flags)
                    print(json.dumps(parsed, indent=2))
                else:
                    print("[*] Done (llm-tools output).")
                return
            else:
                print(json.dumps(result, indent=2))
                return
        except Exception as e:
            print("[!] llm-tools-nmap failed:", e)

    # Fallback
    parsed = run_nmap_direct(target, ports, flags)
    print("[*] Parsed result:")
    print(json.dumps(parsed, indent=2))


if __name__ == "__main__":
    main()
