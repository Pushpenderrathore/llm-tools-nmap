#!/usr/bin/env python3
"""
Ollama + Nmap agent (robustified).

Features / changes from original:
 - Robust import of 'llm-tools-nmap' (tries multiple plausible names).
 - Robust handling of different ollama.chat return shapes (dict, list, generator).
 - Reliable extraction of the first top-level JSON object from model output
   using brace-balancing instead of a greedy regex.
 - Better error handling when trying candidate llm-tools entrypoints.
 - Minor UX and safety improvements.
"""

import argparse
import json
import re
import shlex
import subprocess
import sys
import ipaddress
from typing import Optional, Dict, Any, Iterable
import importlib

# Try to import ollama client (install in venv: pip install ollama)
try:
    import ollama
except Exception:
    print("ERROR: 'ollama' python package not installed in current environment.", file=sys.stderr)
    print("Install in venv: pip install ollama", file=sys.stderr)
    raise

# Try to import llm-tools-nmap (optional). Be flexible about package name.
_llm_tools = None
_llm_candidates = ("llm_tools_nmap", "llm-tools-nmap", "llm_tools.nmap", "llm_tools_nmap_py")
for name in _llm_candidates:
    try:
        _llm_tools = importlib.import_module(name)
        print(f"[*] Imported llm-tools module: {name}")
        break
    except Exception:
        _llm_tools = None

# UTIL: check if address is allowed (private/local) unless force override
def target_allowed(target: str) -> bool:
    """
    Return True if target is loopback or private IP or 'localhost'.
    Note: we do NOT resolve arbitrary hostnames here for safety.
    """
    try:
        ip = ipaddress.ip_address(target)
        return ip.is_loopback or ip.is_private
    except Exception:
        # not an IP (likely hostname) — allow only exact localhost variants
        if target.lower() in ("localhost", "127.0.0.1", "::1"):
            return True
        return False

# UTIL: run nmap and return parsed summary using nmap's XML output
def run_nmap_direct(target: str, ports: Optional[str], flags: Optional[str]) -> Dict[str, Any]:
    cmd = ["nmap", "-oX", "-"]
    if flags:
        cmd += shlex.split(flags)
    if ports:
        cmd += ["-p", ports]
    cmd += [target]
    print("[*] Running:", " ".join(shlex.quote(c) for c in cmd))
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0 and proc.stdout.strip() == "":
        print("[!] nmap returned non-zero exit and no XML. stderr:", proc.stderr.strip(), file=sys.stderr)
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
                hostdict["ports"].append({
                    "port": portnum,
                    "protocol": protocol,
                    "state": state,
                    "service": service
                })
            hosts.append(hostdict)
        return {"hosts": hosts}
    except Exception as e:
        return {"error": f"XML parse error: {e}", "raw_xml": xml}


# UTIL: try to call llm-tools-nmap if available (best-effort)
def run_llm_tools_nmap(target: str, ports: Optional[str], flags: Optional[str]):
    if _llm_tools is None:
        raise ImportError("llm-tools-nmap not importable")

    # candidate function names and expected parameter orders
    candidates = [
        ("run_scan", ("target", "ports", "flags")),
        ("nmap_scan", ("target", "ports", "flags")),
        ("scan", ("target", "ports", "flags")),
        ("do_scan", ("target", "ports", "flags")),
    ]
    last_exc = None
    for name, params in candidates:
        if hasattr(_llm_tools, name):
            fn = getattr(_llm_tools, name)
            try:
                # try keyword call first
                return fn(target=target, ports=ports, flags=flags)
            except TypeError:
                try:
                    # fallback to positional call
                    return fn(target, ports, flags)
                except Exception as e:
                    last_exc = e
                    # don't abort; try next candidate
    if last_exc:
        raise RuntimeError(f"llm-tools-nmap imported but calls failed. Last error: {last_exc}")
    raise RuntimeError("llm-tools-nmap imported but no known entrypoint found")


# Compose system prompt telling model to reply with strict JSON
SYSTEM_INSTRUCTION = """
You are an assistant that must produce JSON ONLY (no extra text) describing a single action.
Valid actions:
  1) {"action":"scan","target":"<ip_or_hostname>","ports":"22,80","flags":"-sS -Pn"}
  2) {"action":"explain","text":"..."}   (assistant should just explain, no scan)
Respond only with the JSON object. If you must ask a question, produce:
  {"action":"question","text":"<your question here>"}
"""

def normalize_ollama_response(resp: Any) -> str:
    """
    Normalize common ollama.chat return shapes to a plain text string.
    Supports:
     - dicts containing 'message', 'content', or 'text'
     - lists of messages
     - generator/iterator of pieces (streaming)
     - fallback to str(resp)
    """
    # streaming generator / iterator (not a str)
    if isinstance(resp, Iterable) and not isinstance(resp, (str, bytes, dict, list)):
        try:
            # consume and join text chunks
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
            # not actually iterable
            pass

    if isinstance(resp, dict):
        # known shapes
        if "message" in resp:
            m = resp.get("message")
            if isinstance(m, dict):
                # content may be text or list/dict
                c = m.get("content")
                if isinstance(c, str):
                    return c
                try:
                    return json.dumps(c)
                except Exception:
                    return str(c)
        if "content" in resp and isinstance(resp["content"], str):
            return resp["content"]
        if "text" in resp and isinstance(resp["text"], str):
            return resp["text"]
        # fallback stringify
        try:
            return json.dumps(resp)
        except Exception:
            return str(resp)

    if isinstance(resp, list):
        # list of messages or strings
        parts = []
        for item in resp:
            if isinstance(item, dict):
                parts.append(normalize_ollama_response(item))
            else:
                parts.append(str(item))
        return "\n".join(parts)

    return str(resp)

def extract_first_json(text: str) -> Optional[str]:
    """
    Return the substring containing the first balanced JSON object found in `text`.
    Uses simple brace-balancing to avoid greedy regex pitfalls.
    """
    start = None
    depth = 0
    for i, ch in enumerate(text):
        if ch == "{":
            if start is None:
                start = i
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start is not None:
                    return text[start:i+1]
    return None

def ask_model_for_action(user_prompt: str, model_name: str = "dolphin-llama3:8b") -> Dict[str, Any]:
    messages = [
        {"role": "system", "content": SYSTEM_INSTRUCTION},
        {"role": "user", "content": user_prompt},
    ]
    resp = ollama.chat(model=model_name, messages=messages)
    text = normalize_ollama_response(resp)
    json_text = extract_first_json(text)
    if not json_text:
        raise ValueError(f"Model did not return JSON. Raw model output:\n{text}")
    # try parse, with a tolerant fallback to single-quote replacement
    try:
        return json.loads(json_text)
    except Exception as e:
        fixed = json_text.replace("'", '"')
        try:
            return json.loads(fixed)
        except Exception:
            raise ValueError(f"Could not parse JSON from model output. Raw:\n{json_text}\nError: {e}")

def main():
    parser = argparse.ArgumentParser(description="Ollama-driven Nmap agent (offline).")
    parser.add_argument("--model", default="dolphin-llama3:8b", help="Ollama model name")
    parser.add_argument("--prompt", help="Initial prompt to the model (if omitted, interactive mode).")
    parser.add_argument("--yes", action="store_true", help="Auto-confirm scans (use with care).")
    parser.add_argument("--force", action="store_true", help="Allow scanning non-private targets (unsafe).")
    args = parser.parse_args()

    model_name = args.model

    if args.prompt:
        user_prompt = args.prompt
    else:
        try:
            print("Enter what you want the assistant to do (examples: 'Scan 127.0.0.1 for SSH and HTTP'):")
            user_prompt = input("> ").strip()
        except KeyboardInterrupt:
            print("\nInterrupted.")
            sys.exit(0)
        if not user_prompt:
            print("No prompt given, exiting.")
            sys.exit(0)

    try:
        action = ask_model_for_action(user_prompt, model_name=model_name)
    except Exception as e:
        print("ERROR parsing model output:", e, file=sys.stderr)
        sys.exit(1)

    print("[*] Model action:", action)

    if action.get("action") == "question":
        print("[MODEL QUESTION] ", action.get("text"))
        sys.exit(0)

    if action.get("action") == "explain":
        print("[MODEL EXPLANATION]\n", action.get("text"))
        sys.exit(0)

    if action.get("action") != "scan":
        print("Unknown action from model:", action.get("action"))
        sys.exit(1)

    target = action.get("target")
    ports = action.get("ports")
    flags = action.get("flags")

    if not target:
        print("No target provided by model.")
        sys.exit(1)

    if not args.force and not target_allowed(target):
        print(f"Refusing to scan '{target}' because it's not localhost/private. Use --force to override.")
        sys.exit(1)

    if not args.yes:
        print(f"About to run Nmap on target {target} (ports={ports}, flags={flags}). Type 'yes' to continue:")
        confirm = input("> ").strip().lower()
        if confirm not in ("y", "yes"):
            print("Aborted by user.")
            sys.exit(0)

    # Try llm-tools-nmap integration first
    if _llm_tools is not None:
        try:
            print("[*] Trying llm-tools-nmap integration...")
            result = run_llm_tools_nmap(target=target, ports=ports, flags=flags)
            print("[*] llm-tools-nmap result:")
            print(json.dumps(result, indent=2))
            sys.exit(0)
        except Exception as e:
            print("[!] llm-tools-nmap integration failed or not applicable:", e, file=sys.stderr)
            print("[*] Falling back to direct nmap run.")

    # Fallback: run nmap directly and parse XML
    res = run_nmap_direct(target=target, ports=ports, flags=flags)
    print("[*] Parsed result:")
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
