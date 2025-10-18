#!/usr/bin/env python3
"""
Ollama + Nmap agent (updated for current 'ollama' python package).

Features:
- Talks to local Ollama model (llama3.2:3b) via ollama Python client.
- Asks model to produce a JSON action describing the scan.
- Tries to use llm-tools-nmap module (if installed/available).
- Falls back to running `nmap` binary and parsing XML output.
- Safety: by default only allows localhost and RFC1918 private addresses.
"""

import argparse
import json
import re
import shlex
import subprocess
import sys
import ipaddress
from typing import Optional, Dict

# Try to import ollama client (install in venv: pip install ollama)
try:
    import ollama
except Exception as e:
    print("ERROR: 'ollama' python package not installed in current environment.")
    print("Install in venv: pip install ollama")
    raise

# Try to import llm-tools-nmap (optional)
_llm_tools = None
try:
    import llm_tools_nmap as _lt
    _llm_tools = _lt
except Exception:
    _llm_tools = None

def target_allowed(target: str) -> bool:
    try:
        ip = ipaddress.ip_address(target)
        if ip.is_loopback or ip.is_private:
            return True
        return False
    except Exception:
        return target.lower() in ("localhost", "127.0.0.1")

def run_nmap_direct(target: str, ports: Optional[str], flags: Optional[str]) -> Dict:
    cmd = ["nmap", "-oX", "-"]
    if flags:
        cmd += shlex.split(flags)
    if ports:
        cmd += ["-p", ports]
    cmd += [target]
    print("[*] Running:", " ".join(shlex.quote(c) for c in cmd))
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0 and proc.stdout.strip() == "":
        print("[!] nmap returned non-zero exit and no XML. stderr:", proc.stderr.strip())
        return {"error": proc.stderr.strip()}
    xml = proc.stdout
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml)
        hosts = []
        for host in root.findall("host"):
            addr = host.find("address")
            ipaddr = addr.get("addr") if addr is not None else None
            hostdict = {"ip": ipaddr, "ports": []}
            ports_el = host.find("ports")
            if ports_el is None:
                hosts.append(hostdict)
                continue
            for p in ports_el.findall("port"):
                portnum = p.get("portid")
                protocol = p.get("protocol")
                state_el = p.find("state")
                state = state_el.get("state") if state_el is not None else None
                service_el = p.find("service")
                service = service_el.get("name") if service_el is not None else None
                hostdict["ports"].append({"port": portnum, "protocol": protocol, "state": state, "service": service})
            hosts.append(hostdict)
        return {"hosts": hosts}
    except Exception as e:
        return {"error": f"XML parse error: {e}", "raw_xml": xml}

def run_llm_tools_nmap(target: str, ports: Optional[str], flags: Optional[str]):
    if _llm_tools is None:
        raise ImportError("llm-tools-nmap not importable")
    for name in ("run_scan", "nmap_scan", "scan", "do_scan"):
        if hasattr(_llm_tools, name):
            fn = getattr(_llm_tools, name)
            try:
                return fn(target=target, ports=ports, flags=flags)
            except TypeError:
                return fn(target, ports, flags)
    raise RuntimeError("llm-tools-nmap imported but no known entrypoint succeeded")

SYSTEM_INSTRUCTION = """
You are an assistant that must produce JSON ONLY (no extra text) describing a single action.
Valid actions:
  1) {"action":"scan","target":"<ip_or_hostname>","ports":"22,80","flags":"-sS -Pn"}
  2) {"action":"explain","text":"..."}
Respond only with the JSON object. If you must ask a question, produce:
  {"action":"question","text":"<your question here>"}
"""

def extract_content_from_ollama_response(resp) -> str:
    if isinstance(resp, dict):
        if "message" in resp:
            m = resp.get("message")
            if isinstance(m, dict) and "content" in m:
                return m["content"]
        if "content" in resp and isinstance(resp["content"], str):
            return resp["content"]
        if "text" in resp and isinstance(resp["text"], str):
            return resp["text"]
        try:
            return json.dumps(resp)
        except Exception:
            return str(resp)
    else:
        return str(resp)

def ask_model_for_action(user_prompt: str, model_name: str = "dolphin-llama3:8b") -> Dict:
    messages = [
        {"role": "system", "content": SYSTEM_INSTRUCTION},
        {"role": "user", "content": user_prompt},
    ]
    resp = ollama.chat(model=model_name, messages=messages)
    text = extract_content_from_ollama_response(resp)
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        raise ValueError(f"Model did not return JSON. Raw model output:\n{text}")
    json_text = m.group(0)
    
    try:
        obj = json.loads(json_text)
        return obj
    except json.JSONDecodeError as e:
        # try to truncate extra text if JSON is followed by non-JSON
        truncated = json_text.split('}')[0] + '}'
        try:
            return json.loads(truncated)
        except Exception:
            raise ValueError(f"Could not parse clean JSON from model output. Raw:\n{json_text}\nError: {e}")

    except Exception:
        fixed = json_text.replace("'", '"')
        return json.loads(fixed)

def print_plain_summary(res: Dict):
    if "error" in res:
        print(f"[!] Error: {res['error']}")
        return
    hosts = res.get("hosts", [])
    if not hosts:
        print(f" NOT FOUND :{hosts}")
        return
    for h in hosts:
        print(f"\nScan results for {h.get('ip', 'unknown host')}:")
        if not h.get("ports"):
            print("  No open ports found.")
            continue
        for p in h["ports"]:
            print(f"  • Port {p['port']}/{p['protocol']} — {p['state']} ({p.get('service','unknown')})")

def main():
    parser = argparse.ArgumentParser(description="Ollama-driven Nmap agent (offline).")
    parser.add_argument("--model", default="dolphin-llama3:8b", help="Ollama model name")
    parser.add_argument("--prompt", help="Initial prompt to the model (if omitted, interactive mode).")
    parser.add_argument("--yes", action="store_true", help="Auto-confirm scans (use with care).")
    parser.add_argument("--force", action="store_true", help="Allow scanning non-private targets (unsafe).")
    args = parser.parse_args()

    model_name = args.model
    user_prompt = args.prompt or input("Enter what you want the assistant to do:\n> ").strip()
    if not user_prompt:
        print("No prompt given, exiting.")
        sys.exit(0)

    try:
        action = ask_model_for_action(user_prompt, model_name=model_name)
    except Exception as e:
        print("ERROR parsing model output:", e)
        sys.exit(1)

    print("[*] Model action:", action)
    if action.get("action") == "question":
        print("[MODEL QUESTION] ", action.get("text"))
        sys.exit(0)
    if action.get("action") == "explain":
        print("[MODEL EXPLANATION]\n", action.get("text"))
        sys.exit(0)
    if action.get("action") != "scan":
        print("Unknown action:", action.get("action"))
        sys.exit(1)

    target = action.get("target")
    ports = action.get("ports")
    flags = action.get("flags")
    if not target:
        print("No target provided by model.")
        sys.exit(1)
    if not args.force and not target_allowed(target):
        print(f"Refusing to scan '{target}' (not private). Use --force to override.")
        sys.exit(1)
    if not args.yes:
        print(f"About to run Nmap on {target} (ports={ports}, flags={flags}). Type 'yes' to continue:")
        if input("> ").strip().lower() not in ("y", "yes"):
            print("Aborted.")
            sys.exit(0)

    result = None
    if _llm_tools is not None:
        try:
            print("[*] Trying llm-tools-nmap integration...")
            result = run_llm_tools_nmap(target=target, ports=ports, flags=flags)
            print_plain_summary(result)
            sys.exit(0)
        except Exception as e:
            print("[!] llm-tools-nmap failed:", e)
            print("[*] Falling back to direct nmap run.")

    res = run_nmap_direct(target=target, ports=ports, flags=flags)
    print_plain_summary(res)

if __name__ == "__main__":
    main()
