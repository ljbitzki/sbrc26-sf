#!/usr/bin/env python3
"""
SBRC26 Testbed de Ataques — versão CLI
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import textwrap
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from modules.registry import CATEGORIES, AttackSpec, ParamSpec
from modules.runners import (
    docker_available,
    docker_container_status,
    docker_logs,
    docker_rm_force,
)
from modules.features import (
    FEATURES_DIR,
    TMP_DIR,
    build_feature_paths,
    extract_with_ntlflowlyzer,
    extract_with_tshark,
    extract_with_scapy,
)
from modules.datasets import build_dataset_unsupervised_for_capture


# -----------------------------
# Diretórios / Paths
# -----------------------------
CAPTURES_DIR = Path("captures")
DATASETS_DIR = Path("datasets")


def _ensure_dirs() -> None:
    CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
    FEATURES_DIR.mkdir(parents=True, exist_ok=True)
    DATASETS_DIR.mkdir(parents=True, exist_ok=True)
    TMP_DIR.mkdir(parents=True, exist_ok=True)


def stem_no_ext(p: Path) -> str:
    return p.name[:-5] if p.name.lower().endswith(".pcap") else p.stem


def build_capture_path(attack_id: str) -> Path:
    _ensure_dirs()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return CAPTURES_DIR / f"{attack_id}-{ts}.pcap"


def build_dataset_path_for_capture(pcap_path: Path) -> Path:
    base = stem_no_ext(pcap_path)
    _ensure_dirs()
    return DATASETS_DIR / f"unsupervised-{base}.csv"


# -----------------------------
# Execução (binary-safe)
# -----------------------------
def _run(cmd: List[str]) -> Tuple[int, str, str]:
    p = subprocess.run(cmd, capture_output=True)
    stdout = (p.stdout or b"").decode("utf-8", errors="replace").strip()
    stderr = (p.stderr or b"").decode("utf-8", errors="replace").strip()
    return p.returncode, stdout, stderr


def _die(msg: str, code: int = 1) -> None:
    print(f"ERRO: {msg}", file=sys.stderr)
    raise SystemExit(code)


def _warn(msg: str) -> None:
    print(f"AVISO: {msg}", file=sys.stderr)


def _ok(msg: str) -> None:
    print(f"OK: {msg}")


# -----------------------------
# Render simples de tabelas
# -----------------------------
def _as_table(rows: List[Dict[str, Any]], headers: Optional[List[str]] = None) -> str:
    if not rows:
        return "(vazio)"
    if headers is None:
        headers = list(rows[0].keys())

    def s(x: Any) -> str:
        return "" if x is None else str(x)

    widths = {h: len(h) for h in headers}
    for r in rows:
        for h in headers:
            widths[h] = max(widths[h], len(s(r.get(h, ""))))

    line = " | ".join(h.ljust(widths[h]) for h in headers)
    sep = "-+-".join("-" * widths[h] for h in headers)
    out = [line, sep]
    for r in rows:
        out.append(" | ".join(s(r.get(h, "")).ljust(widths[h]) for h in headers))
    return "\n".join(out)


def format_bytes(n: int) -> str:
    x = float(n)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if x < 1024 or unit == "TB":
            return f"{x:.0f} {unit}" if unit == "B" else f"{x:.1f} {unit}"
        x /= 1024
    return f"{x:.1f} TB"


# -----------------------------
# Host IP
# -----------------------------
def get_host_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "-"


# -----------------------------
# MITRE/Tools labels
# -----------------------------
_MITRE_PATH_RE = re.compile(
    r"/(?P<kind>techniques|tactics)/(?P<id>[^/?#]+(?:/[^/?#]+)?)",
    re.IGNORECASE,
)


def mitre_label_from_url(url: str) -> str:
    m = _MITRE_PATH_RE.search(url)
    if not m:
        return url.rstrip("/")
    return m.group("id").rstrip("/")


def normalize_mitre(mitre: Optional[Any]) -> List[str]:
    if not mitre:
        return []
    if isinstance(mitre, str):
        return [mitre]
    if isinstance(mitre, list):
        return [m for m in mitre if isinstance(m, str) and m.strip()]
    return []


def normalize_tools(tools: Optional[List[Dict[str, str]]]) -> List[Dict[str, str]]:
    if not tools:
        return []
    norm: List[Dict[str, str]] = []
    for item in tools:
        if not isinstance(item, dict) or not item:
            continue
        if "name" in item and "url" in item:
            name = str(item.get("name", "")).strip()
            url = str(item.get("url", "")).strip()
            if name and url:
                norm.append({"name": name, "url": url})
            continue
        if len(item) == 1:
            name, url = next(iter(item.items()))
            name = str(name).strip()
            url = str(url).strip()
            if name and url:
                norm.append({"name": name, "url": url})
    return norm

# -----------------------------
# Captura tcpdump
# -----------------------------
def start_tcpdump_capture(pcap_path: Path, iface: str = "docker0") -> Dict[str, Any]:
    _ensure_dirs()
    cmd = ["tcpdump", "-i", iface, "-w", str(pcap_path)]
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(0.25)
        if p.poll() is not None:
            out = (p.stdout.read() if p.stdout else b"")
            err = (p.stderr.read() if p.stderr else b"")
            return {
                "ok": False,
                "cmd": cmd,
                "popen": None,
                "stdout": (out or b"").decode("utf-8", errors="replace").strip(),
                "stderr": (err or b"").decode("utf-8", errors="replace").strip(),
            }
        return {"ok": True, "cmd": cmd, "popen": p, "stdout": "", "stderr": ""}
    except FileNotFoundError:
        return {"ok": False, "cmd": cmd, "popen": None, "stdout": "", "stderr": "tcpdump não encontrado no PATH."}
    except Exception as e:
        return {"ok": False, "cmd": cmd, "popen": None, "stdout": "", "stderr": str(e)}

def stop_tcpdump_capture(p: subprocess.Popen, timeout: float = 3.0) -> Dict[str, Any]:
    try:
        if p.poll() is None:
            p.send_signal(signal.SIGINT)
            try:
                p.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                p.terminate()
                try:
                    p.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    p.kill()
        out = (p.stdout.read() if p.stdout else b"")
        err = (p.stderr.read() if p.stderr else b"")
        return {
            "ok": True,
            "stdout": (out or b"").decode("utf-8", errors="replace").strip(),
            "stderr": (err or b"").decode("utf-8", errors="replace").strip(),
        }
    except Exception as e:
        return {"ok": False, "stdout": "", "stderr": str(e)}

# -----------------------------
# Servidores
# -----------------------------
SERVER_SPECS: List[Tuple[str, str]] = [
    ("Web Server", "sbrc26-servidor-http-server"),
    ("SSH Server", "sbrc26-servidor-ssh-server"),
    ("SMB Server", "sbrc26-servidor-smb-server"),
    ("MQTT Broker", "sbrc26-servidor-mqtt-broker"),
    ("CoAP Server", "sbrc26-servidor-coap-server"),
    ("Telnet Server", "sbrc26-servidor-telnet-server"),
    ("SSL Heartbleed", "sbrc26-servidor-ssl-heartbleed"),
]

SERVER_KEY_TO_IMAGE = {
    "web": "sbrc26-servidor-http-server",
    "ssh": "sbrc26-servidor-ssh-server",
    "smb": "sbrc26-servidor-smb-server",
    "mqtt": "sbrc26-servidor-mqtt-broker",
    "coap": "sbrc26-servidor-coap-server",
    "telnet": "sbrc26-servidor-telnet-server",
    "ssl": "sbrc26-servidor-ssl-heartbleed",
}

SERVER_RUN_CMDS: Dict[str, List[str]] = {
    "sbrc26-servidor-http-server": ["docker", "run", "-d", "--rm", "--name", "sbrc26-servidor-http-server", "-p", "8080:80", "sbrc26-servidor-http-server:latest"],
    "sbrc26-servidor-ssh-server": ["docker", "run", "-d", "--rm", "--name", "sbrc26-servidor-ssh-server", "-p", "2222:22", "sbrc26-servidor-ssh-server:latest"],
    "sbrc26-servidor-smb-server": [
        "docker",
        "run",
        "-it",
        "-d",
        "--rm",
        "--name",
        "sbrc26-servidor-smb-server",
        "-p",
        "139:139",
        "-p",
        "445:445",
        "-p",
        "137:137/udp",
        "-p",
        "138:138/udp",
        "sbrc26-servidor-smb-server:latest",
        "-g",
        "log level = 3",
        "-s",
        "public;/share",
        "-u",
        "example2;badpass",
    ],
    "sbrc26-servidor-mqtt-broker": ["docker", "run", "-d", "--rm", "--name", "sbrc26-servidor-mqtt-broker", "-p", "1883:1883", "-p", "9001:9001", "sbrc26-servidor-mqtt-broker:latest"],
    "sbrc26-servidor-coap-server": ["docker", "run", "-d", "--rm", "--name", "sbrc26-servidor-coap-server", "-p", "5683:5683", "-p", "5683:5683/udp", "sbrc26-servidor-coap-server:latest"],
    "sbrc26-servidor-telnet-server": ["docker", "run", "-d", "--rm", "--name", "sbrc26-servidor-telnet-server", "-p", "2323:23", "sbrc26-servidor-telnet-server:latest"],
    "sbrc26-servidor-ssl-heartbleed": ["docker", "run", "-d", "--rm", "--name", "sbrc26-servidor-ssl-heartbleed", "-p", "8443:443", "sbrc26-servidor-ssl-heartbleed:latest"],
}

SERVER_LOG_SPECS: Dict[str, Dict[str, Any]] = {
    "sbrc26-servidor-coap-server": {"mode": "docker_logs"},
    "sbrc26-servidor-http-server": {"mode": "docker_logs"},
    "sbrc26-servidor-mqtt-broker": {"mode": "docker_logs"},
    "sbrc26-servidor-smb-server": {"mode": "exec_sh", "sh": "/var/log/samba/*"},
    "sbrc26-servidor-ssh-server": {"mode": "exec_sh", "sh": "/var/log/auth.log"},
    "sbrc26-servidor-ssl-heartbleed": {"mode": "exec_sh", "sh": "/var/log/access.log"},
    "sbrc26-servidor-telnet-server": {
        "mode": "exec_sh",
        "sh": "/var/log/wtmp",
        "binary": True,
        "binary_hint": "O arquivo /var/log/wtmp é binário; o modo Tail raw pode ser ilegível.",
        "alt_label": "Usar last",
        "alt_sh": 'command -v last >/dev/null 2>&1 && last -f /var/log/wtmp || echo "Comando last não está disponível no container."',
    },
}

def _container_ids_by_ancestor(image: str) -> List[str]:
    rc, out, _ = _run(["docker", "ps", "-a", "-q", "--filter", f"ancestor={image}"])
    ids = [x for x in out.splitlines() if x.strip()] if rc == 0 else []
    if not ids and ":" not in image:
        rc, out, _ = _run(["docker", "ps", "-a", "-q", "--filter", f"ancestor={image}:latest"])
        ids = [x for x in out.splitlines() if x.strip()] if rc == 0 else []
    return ids

def _inspect(cont_id: str) -> Optional[dict]:
    rc, out, _ = _run(["docker", "inspect", cont_id])
    if rc != 0 or not out:
        return None
    try:
        data = json.loads(out)
        return data[0] if data else None
    except Exception:
        return None

def _extract_ips(inspected: dict) -> Dict[str, str]:
    ips: Dict[str, str] = {}
    nets = (inspected.get("NetworkSettings") or {}).get("Networks") or {}
    for net_name, net_data in nets.items():
        ip = (net_data or {}).get("IPAddress") or ""
        if ip:
            ips[net_name] = ip
    return ips


def _pick_preferred_container(container_ids: List[str]) -> Optional[str]:
    if not container_ids:
        return None
    for cid in container_ids:
        inspected = _inspect(cid)
        if not inspected:
            continue
        status = ((inspected.get("State") or {}).get("Status") or "").lower()
        if status == "running":
            return cid
    return container_ids[0]


def get_servers_status_rows() -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = [{"Servidor": "Esta máquina", "IP": get_host_ip()}]
    if not docker_available():
        rows.append({"Servidor": "Docker", "IP": "Docker indisponível (CLI não acessível)."})
        return rows
    for label, image in SERVER_SPECS:
        ids = _container_ids_by_ancestor(image)
        cid = _pick_preferred_container(ids)
        if not cid:
            rows.append({"Servidor": label, "IP": "-"})
            continue
        inspected = _inspect(cid)
        if not inspected:
            rows.append({"Servidor": label, "IP": "-"})
            continue
        ips = _extract_ips(inspected)
        ip = ips.get("bridge") or (next(iter(ips.values())) if ips else "-")
        rows.append({"Servidor": label, "IP": ip})
    return rows

def servers_stop_all() -> None:
    if not docker_available():
        _die("Docker indisponível.")
    rc, out, err = _run(["docker", "ps", "-a", "--format", "{{.Names}}"])
    if rc != 0:
        _die(err or "Falha ao listar containers.")
    names = [n.strip() for n in out.splitlines() if n.strip().startswith("sbrc26-servidor-")]
    if not names:
        _ok("Nenhum servidor para remover.")
        return
    rc, out, err = _run(["docker", "rm", "-f", *names])
    if rc != 0:
        _die(err or out or "Falha ao remover containers de servidores.")
    _ok(f"Servidores removidos: {', '.join(names)}")

def servers_start_all() -> None:
    if not docker_available():
        _die("Docker indisponível.")
    rc, out, err = _run(["docker", "ps", "-a", "--format", "{{.Names}}"])
    if rc != 0:
        _die(err or "Falha ao listar containers.")
    existing = {n.strip() for n in out.splitlines() if n.strip()}

    started: List[str] = []
    for _, image_base in SERVER_SPECS:
        name = image_base
        if name in existing:
            continue
        cmd = SERVER_RUN_CMDS.get(image_base)
        if not cmd:
            _warn(f"Sem comando de start definido para {image_base}")
            continue
        rc, out, err = _run(cmd)
        if rc != 0:
            _die(f"Falha ao iniciar {image_base}: {err or out}")
        started.append(image_base)
    if started:
        _ok(f"Servidores iniciados: {', '.join(started)}")
    else:
        _ok("Todos os servidores já estavam criados.")

def get_server_image_from_key(key_or_image: str) -> str:
    k = key_or_image.strip().lower()
    return SERVER_KEY_TO_IMAGE.get(k, key_or_image.strip())

def fetch_server_logs(image_base: str, tail_lines: int = 200, prefer_alt: bool = False) -> Dict[str, Any]:
    if not docker_available():
        return {"ok": False, "mode": "error", "cmd_display": "", "stdout": "", "stderr": "Docker indisponível.", "returncode": 1}

    ids = _container_ids_by_ancestor(image_base)
    cid = _pick_preferred_container(ids)
    if not cid:
        return {"ok": False, "mode": "error", "cmd_display": "", "stdout": "", "stderr": f"Container não encontrado para ancestor={image_base}.", "returncode": 1}

    spec = SERVER_LOG_SPECS.get(image_base, {"mode": "docker_logs"})
    mode = spec.get("mode", "docker_logs")
    tail_lines = max(1, min(int(tail_lines), 5000))

    if mode == "docker_logs":
        cmd = ["docker", "logs", "--tail", str(tail_lines), cid]
        rc, out, err = _run(cmd)
        return {"ok": rc == 0, "mode": mode, "cmd_display": " ".join(cmd), "stdout": out, "stderr": err, "returncode": rc}

    if mode == "exec_sh":
        if prefer_alt and spec.get("alt_sh"):
            sh_cmd = f"{spec['alt_sh']} | head -n {tail_lines}"
            cmd = ["docker", "exec", cid, "sh", "-lc", sh_cmd]
            rc, out, err = _run(cmd)
            return {"ok": True, "mode": mode, "cmd_display": " ".join(cmd), "stdout": out, "stderr": err, "returncode": rc}

        files_expr = spec.get("sh", "")
        sh_cmd = f"tail -n {tail_lines} {files_expr} 2>/dev/null || true"
        cmd = ["docker", "exec", cid, "sh", "-lc", sh_cmd]
        rc, out, err = _run(cmd)
        return {"ok": True, "mode": mode, "cmd_display": " ".join(cmd), "stdout": out, "stderr": err, "returncode": rc}

    return {"ok": False, "mode": "error", "cmd_display": "", "stdout": "", "stderr": f"Modo de log desconhecido: {mode}", "returncode": 1}

# -----------------------------
# Clientes benignos simples
# -----------------------------
CLIENT_NAME_RE = re.compile(r"^sbrc26-cliente-(\d{1,2})$")
CLIENT_IMAGE = "sbrc26-clientes:latest"
CLIENT_NAME_PREFIX = "sbrc26-cliente-"
CLIENT_MAX_RUNNING = 10

BENIGN_CLIENT_SERVER_ORDER: List[Tuple[str, str]] = [
    ("WEB", "sbrc26-servidor-http-server"),
    ("SSH", "sbrc26-servidor-ssh-server"),
    ("SMB", "sbrc26-servidor-smb-server"),
    ("MQTT", "sbrc26-servidor-mqtt-broker"),
    ("COAP", "sbrc26-servidor-coap-server"),
    ("TELNET", "sbrc26-servidor-telnet-server"),
    ("SSL", "sbrc26-servidor-ssl-heartbleed"),
]

def list_running_benign_clients() -> List[Tuple[str, int]]:
    if not docker_available():
        return []
    rc, out, _ = _run(["docker", "ps", "--format", "{{.Names}}"])
    if rc != 0:
        return []
    items: List[Tuple[str, int]] = []
    for name in out.splitlines():
        name = name.strip()
        m = CLIENT_NAME_RE.match(name)
        if m:
            items.append((name, int(m.group(1))))
    items.sort(key=lambda x: x[1])
    return items

def get_running_container_id_by_ancestor(image_base: str) -> Optional[str]:
    if not docker_available():
        return None
    rc, out, _ = _run(["docker", "ps", "--filter", f"ancestor={image_base}:latest", "--format", "{{.ID}}"])
    ids = [x.strip() for x in out.splitlines() if x.strip()]
    if rc == 0 and ids:
        return ids[0]
    rc, out, _ = _run(["docker", "ps", "--filter", f"ancestor={image_base}", "--format", "{{.ID}}"])
    ids = [x.strip() for x in out.splitlines() if x.strip()]
    if rc == 0 and ids:
        return ids[0]
    return None

def get_container_ip_by_id(cid: str) -> Optional[str]:
    if not cid:
        return None
    rc, out, _ = _run([
        "docker",
        "inspect",
        "-f",
        "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}",
        cid,
    ])
    if rc != 0:
        return None
    ips = [x for x in out.strip().split() if x]
    return ips[0] if ips else None

def get_required_server_ips() -> Tuple[Optional[List[str]], List[str]]:
    missing: List[str] = []
    ips: List[str] = []
    for label, image_base in BENIGN_CLIENT_SERVER_ORDER:
        cid = get_running_container_id_by_ancestor(image_base)
        if not cid:
            missing.append(label)
            continue
        ip = get_container_ip_by_id(cid)
        if not ip:
            missing.append(label)
            continue
        ips.append(ip)
    if missing:
        return None, missing
    return ips, []

def next_benign_client_number(running_clients: List[Tuple[str, int]]) -> int:
    if not running_clients:
        return 1
    return max(n for _, n in running_clients) + 1

def remove_all_benign_clients() -> None:
    running_clients = list_running_benign_clients()
    if not docker_available():
        _die("Docker indisponível.")
    if not running_clients:
        _ok("Nenhum cliente para remover.")
        return
    names = [name for name, _ in running_clients]
    rc, out, err = _run(["docker", "rm", "-f", *names])
    if rc != 0:
        _die(err or out or "Falha ao remover clientes.")
    _ok(f"Clientes removidos: {', '.join(names)}")

def start_one_benign_client() -> None:
    if not docker_available():
        _die("Docker indisponível.")
    running_clients = list_running_benign_clients()
    if len(running_clients) >= CLIENT_MAX_RUNNING:
        _die("Limite de 10 clientes benignos já atingido.")

    server_ips, missing = get_required_server_ips()
    if not server_ips:
        _die("Não é possível iniciar cliente: servidor(es) não estão rodando/sem IP: " + ", ".join(missing))

    y = next_benign_client_number(running_clients)
    name = f"{CLIENT_NAME_PREFIX}{y}"
    cmd = ["docker", "run", "-d", "--rm", "--name", name, CLIENT_IMAGE, *server_ips]
    rc, out, err = _run(cmd)
    if rc != 0:
        _die(err or out or "Falha ao iniciar cliente benigno.")
    _ok(f"Iniciado: {name} (servers: {', '.join(server_ips)})")

# -----------------------------
# Ataques
# -----------------------------
def all_attacks() -> List[AttackSpec]:
    items: List[AttackSpec] = []
    for _, attacks in CATEGORIES.items():
        items.extend(attacks)
    return items

def attack_by_id(attack_id: str) -> AttackSpec:
    for a in all_attacks():
        if a.id == attack_id:
            return a
    _die(f"Ataque não encontrado: {attack_id}")
    raise AssertionError("unreachable")

def validate_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except Exception:
        return False

def validate_port(value: int) -> bool:
    return 1 <= int(value) <= 65535

def validate_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value.strip(), strict=False)
        return True
    except Exception:
        return False

def resolve_placeholder(p: ParamSpec, host_ip: str) -> str:
    ph = getattr(p, "placeholder", None)
    if not ph:
        return ""
    return host_ip if ph == "__HOST_IP__" else str(ph)

def validate_params(spec: AttackSpec, params: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    for p in spec.params:
        v = params.get(p.key, "")
        if p.kind == "ip":
            if not v or not validate_ip(str(v)):
                errors.append(f'Campo "{p.label}" inválido.')
        elif p.kind == "cidr":
            if not v or not validate_cidr(str(v)):
                errors.append(f'Campo "{p.label}" inválido (ex.: 192.168.0.0/24).')
        elif p.kind == "port":
            try:
                pv = int(v)
                if not validate_port(pv):
                    errors.append(f'Campo "{p.label}" inválido (1–65535).')
            except Exception:
                errors.append(f'Campo "{p.label}" inválido (1–65535).')
        else:
            if v is None:
                errors.append(f'Campo "{p.label}" inválido.')
    return errors

def _prompt(text: str, default: Optional[str] = None) -> str:
    if default is not None and default != "":
        s = input(f"{text} [{default}]: ").strip()
        return s if s else default
    return input(f"{text}: ").strip()

def prompt_params_interactive(spec: AttackSpec) -> Dict[str, Any]:
    host_ip = get_host_ip()
    resolved: Dict[str, Any] = {}
    if not spec.params:
        return resolved

    print("\nParâmetros:")
    for p in spec.params:
        ph = resolve_placeholder(p, host_ip)
        default = ""
        if p.kind == "port":
            if p.default is not None:
                default = str(int(p.default))
            elif ph.isdigit():
                default = ph
            else:
                default = "1"
            while True:
                v = _prompt(f"- {p.label} (porta)", default=default)
                try:
                    pv = int(v)
                except Exception:
                    print("  -> inválido (esperado inteiro 1–65535)")
                    continue
                if not validate_port(pv):
                    print("  -> inválido (faixa 1–65535)")
                    continue
                resolved[p.key] = pv
                break
            continue

        # ip/cidr/text
        default = str(p.default) if p.default is not None else (ph if ph else "")
        while True:
            kind_label = p.kind
            v = _prompt(f"- {p.label} ({kind_label})", default=default if default else None)
            if p.kind == "ip" and not validate_ip(v):
                print("  -> inválido (IP)")
                continue
            if p.kind == "cidr" and not validate_cidr(v):
                print("  -> inválido (CIDR)")
                continue
            resolved[p.key] = v
            break

    return resolved

def parse_kv_list(pairs: Optional[List[str]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for raw in pairs or []:
        if "=" not in raw:
            _die(f"Parâmetro inválido (use key=value): {raw}")
        k, v = raw.split("=", 1)
        k = k.strip()
        v = v.strip()
        if not k:
            _die(f"Parâmetro inválido (chave vazia): {raw}")
        out[k] = v
    return out

def coerce_params_types(spec: AttackSpec, params: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(params)
    for p in spec.params:
        if p.key not in out:
            continue
        if p.kind == "port":
            try:
                out[p.key] = int(out[p.key])
            except Exception:
                pass
    return out

def run_attack(
    spec: AttackSpec,
    resolved_params: Dict[str, Any],
    *,
    capture_enabled: bool = True,
    iface: str = "docker0",
    wait: bool = True,
    capture_seconds: Optional[int] = None,
) -> Dict[str, Any]:
    if not docker_available():
        return {"ok": False, "stderr": "Docker indisponível no host.", "cmd": [], "returncode": 1}

    # sem captura: apenas dispara container
    if not capture_enabled:
        result = spec.runner(resolved_params)
        result["capture"] = {"enabled": False}
        return result

    pcap_path = build_capture_path(spec.id)
    cap = start_tcpdump_capture(pcap_path, iface=iface)
    if not cap.get("ok"):
        return {
            "ok": False,
            "stderr": f"Falha ao iniciar captura: {cap.get('stderr') or ''}".strip(),
            "cmd": cap.get("cmd", []),
            "returncode": 1,
            "capture": {"enabled": True, "ok": False, "pcap_path": str(pcap_path), **cap},
        }

    tcpdump_p = cap["popen"]
    wait_err = ""
    attack_result: Dict[str, Any] = {}
    try:
        attack_result = spec.runner(resolved_params)
        container_id = attack_result.get("container_id")
        if wait and container_id:
            rc, out, err = _run(["docker", "wait", container_id])
            if rc != 0:
                wait_err = err or out or "Falha ao aguardar término do container."
        elif capture_seconds is not None:
            time.sleep(max(0, int(capture_seconds)))
        elif not wait:
            time.sleep(10)
            wait_err = "Execução em modo --no-wait: captura finalizada após 10s (use --capture-seconds para ajustar)."
    finally:
        stop_info = stop_tcpdump_capture(tcpdump_p)
        attack_result["capture"] = {
            "enabled": True,
            "ok": True,
            "pcap_path": str(pcap_path),
            "tcpdump_cmd": cap.get("cmd"),
            "wait_error": wait_err,
            "stop": stop_info,
        }
    return attack_result

def print_attack_details(spec: AttackSpec) -> None:
    print(f"ID: {spec.id}")
    print(f"Nome: {spec.name}")
    print(f"Descrição: {spec.description}")
    print(f"Image: {spec.image}")
    print(f"Container (nome): {spec.container_name}")
    if getattr(spec, "details_warning", None):
        print(f"\n[AVISO] {spec.details_warning}")

    tools = normalize_tools(getattr(spec, "tools", None))
    if tools:
        print("\nFerramentas:")
        for t in tools:
            print(f"- {t['name']}: {t['url']}")

    mitre = normalize_mitre(getattr(spec, "mitre", None))
    if mitre:
        print("\nMITRE ATT&CK:")
        for u in mitre:
            print(f"- {mitre_label_from_url(u)}: {u}")

def attack_status(spec: AttackSpec) -> None:
    if not spec.container_name:
        print("Este ataque não possui container_name; status indisponível.")
        return
    st = docker_container_status(spec.container_name)
    if not st.get("exists"):
        print("Status: parado (container não encontrado).")
        return
    print(f"Status: {st.get('status', 'unknown')}")
    print(f"Container ID: {st.get('id') or '-'}")

def attack_stop(spec: AttackSpec) -> None:
    if not spec.container_name:
        _die("Este ataque não possui container_name definido; não é possível parar automaticamente.")
    if not docker_available():
        _die("Docker indisponível.")
    res = docker_rm_force(spec.container_name)
    if res.get("ok"):
        _ok("Container do ataque removido.")
    else:
        _die(res.get("stderr") or res.get("stdout") or "Falha ao remover container do ataque.")

def attack_show_logs(spec: AttackSpec, tail: int = 200) -> None:
    if not spec.container_name:
        _die("Este ataque não possui container_name definido; não é possível buscar logs.")
    logs = docker_logs(spec.container_name, tail=int(tail))
    if logs.get("ok") and logs.get("stdout"):
        print(logs["stdout"])
    elif logs.get("stderr"):
        print(logs["stderr"], file=sys.stderr)
    else:
        print("(sem logs)")

# -----------------------------
# Capturas / Features / Dataset
# -----------------------------
def list_capture_files() -> List[Path]:
    _ensure_dirs()
    return sorted(CAPTURES_DIR.glob("*.pcap"), key=lambda p: p.stat().st_mtime, reverse=True)

def captures_list(filter_substr: str = "") -> None:
    files = list_capture_files()
    q = (filter_substr or "").strip().lower()
    if q:
        files = [p for p in files if q in p.name.lower()]
    if not files:
        print(f"Nenhuma captura encontrada em {CAPTURES_DIR}/")
        return
    rows: List[Dict[str, Any]] = []
    for p in files:
        stat = p.stat()
        outs = build_feature_paths(p)
        has_features = any(path.exists() for path in outs.values())
        ds_path = build_dataset_path_for_capture(p)
        has_dataset = ds_path.exists()
        rows.append(
            {
                "Arquivo": p.name,
                "Tamanho": format_bytes(stat.st_size),
                "Modificado": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                "Features": "sim" if has_features else "não",
                "Dataset": "sim" if has_dataset else "não",
            }
        )
    print(_as_table(rows))

def _resolve_capture_path(s: str) -> Path:
    p = Path(s)
    if p.is_file():
        return p
    # tenta em captures/
    p2 = CAPTURES_DIR / s
    if p2.is_file():
        return p2
    _die(f"Arquivo de captura não encontrado: {s}")
    raise AssertionError("unreachable")

def captures_info(pcap: Path) -> None:
    stat = pcap.stat()
    outs = build_feature_paths(pcap)
    ds_path = build_dataset_path_for_capture(pcap)
    print(f"Arquivo: {pcap}")
    print(f"Tamanho: {format_bytes(stat.st_size)}")
    print(f"Modificado: {datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')}")
    print("\nFeatures previstas:")
    for k, v in outs.items():
        print(f"- {k}: {v} ({'existe' if v.exists() else 'não existe'})")
    print(f"\nDataset: {ds_path} ({'existe' if ds_path.exists() else 'não existe'})")

def captures_export(pcap: Path, dest: Path) -> None:
    dest = Path(dest)
    if dest.is_dir():
        dest = dest / pcap.name
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(pcap, dest)
    _ok(f"Exportado para: {dest}")

def captures_extract_features(
    pcap: Path,
    *,
    run_ntl: bool,
    run_tshark: bool,
    run_scapy: bool,
    overwrite: bool,
) -> None:
    outs = build_feature_paths(pcap)
    results: Dict[str, Any] = {}
    if run_ntl:
        results["ntlflowlyzer"] = (
            extract_with_ntlflowlyzer(pcap, outs["ntlflowlyzer"])
            if (overwrite or not outs["ntlflowlyzer"].exists())
            else {"ok": True, "output": str(outs["ntlflowlyzer"]), "cmd": ["(skip) já existe"]}
        )
    if run_tshark:
        results["tshark"] = (
            extract_with_tshark(pcap, outs["tshark"])
            if (overwrite or not outs["tshark"].exists())
            else {"ok": True, "output": str(outs["tshark"]), "cmd": ["(skip) já existe"]}
        )
    if run_scapy:
        results["scapy"] = (
            extract_with_scapy(pcap, outs["scapy"])
            if (overwrite or not outs["scapy"].exists())
            else {"ok": True, "output": str(outs["scapy"]), "cmd": ["(skip) já existe"]}
        )

    for tool, res in results.items():
        if res.get("ok"):
            _ok(f"{tool}: OK → {res.get('output')}")
        else:
            print(f"{tool}: FALHOU")
            if res.get("stderr"):
                print(res["stderr"], file=sys.stderr)
        if res.get("cmd"):
            print("  cmd:", " ".join(res["cmd"]))

def _preview_csv(path: Path, n_rows: int) -> List[List[str]]:
    rows: List[List[str]] = []
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        r = csv.reader(f)
        for i, row in enumerate(r):
            rows.append(row)
            if i >= n_rows:
                break
    return rows

def captures_view_features(pcap: Path, tool: str, rows: int) -> None:
    outs = build_feature_paths(pcap)
    if tool not in outs:
        _die(f"Tool inválida: {tool} (use: {', '.join(sorted(outs.keys()))})")
    csv_path = outs[tool]
    if not csv_path.exists():
        _die(f"CSV não encontrado: {csv_path}")
    print(f"Arquivo: {csv_path}")
    data = _preview_csv(csv_path, max(1, int(rows)))
    for row in data:
        print(",".join(row))

def captures_build_dataset(pcap: Path) -> None:
    out = build_dataset_unsupervised_for_capture(pcap, features_dir=FEATURES_DIR, outdir=DATASETS_DIR)
    _ok(f"Dataset gerado: {out}")

def captures_view_dataset(pcap: Path, rows: int, cols: int, search: str) -> None:
    ds_path = build_dataset_path_for_capture(pcap)
    if not ds_path.exists():
        _die(f"Dataset não encontrado: {ds_path}")
    try:
        import pandas as pd  # type: ignore

        df = pd.read_csv(ds_path, nrows=int(rows), engine="python")
        if df.shape[1] > int(cols):
            df = df.iloc[:, : int(cols)]
        q = (search or "").strip().lower()
        if q:
            mask = df.astype(str).agg(" ".join, axis=1).str.lower().str.contains(q, na=False)
            df = df[mask]

        print(f"Arquivo: {ds_path}")
        print(f"Linhas exibidas: {len(df)} (até {rows}), Colunas: {df.shape[1]}")
        # saída simples CSV para terminal
        print(df.to_csv(index=False))
        return
    except Exception as e:
        _warn(f"Pandas indisponível ou falhou ao ler CSV ({e}). Usando leitura simples.")

    q = (search or "").strip().lower()
    printed = 0
    with ds_path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        r = csv.reader(f)
        for i, row in enumerate(r):
            if i == 0:
                print(",".join(row[: int(cols)]))
                continue
            line = ",".join(row[: int(cols)])
            if q and q not in line.lower():
                continue
            print(line)
            printed += 1
            if printed >= int(rows):
                break

# -----------------------------
# Interface: comandos
# -----------------------------
def cmd_attack_list(_args: argparse.Namespace) -> None:
    rows: List[Dict[str, Any]] = []
    for cat, attacks in CATEGORIES.items():
        for a in attacks:
            rows.append({"Categoria": cat, "ID": a.id, "Nome": a.name, "Imagem": a.image})
    print(_as_table(rows, headers=["Categoria", "ID", "Nome", "Imagem"]))

def cmd_attack_info(args: argparse.Namespace) -> None:
    spec = attack_by_id(args.attack_id)
    print_attack_details(spec)

def cmd_attack_status(args: argparse.Namespace) -> None:
    spec = attack_by_id(args.attack_id)
    attack_status(spec)

def cmd_attack_stop(args: argparse.Namespace) -> None:
    spec = attack_by_id(args.attack_id)
    attack_stop(spec)

def cmd_attack_logs(args: argparse.Namespace) -> None:
    spec = attack_by_id(args.attack_id)
    attack_show_logs(spec, tail=args.tail)

def cmd_attack_run(args: argparse.Namespace) -> None:
    spec = attack_by_id(args.attack_id)

    # params via --param key=value
    params_cli = parse_kv_list(args.param)
    resolved: Dict[str, Any] = {}
    host_ip = get_host_ip()
    for p in spec.params:
        if p.key in params_cli:
            resolved[p.key] = params_cli[p.key]
            continue
        ph = resolve_placeholder(p, host_ip)
        if p.default is not None:
            resolved[p.key] = p.default
        elif ph:
            resolved[p.key] = ph

    if args.interactive_params:
        missing = [p for p in spec.params if p.key not in resolved or resolved[p.key] in (None, "")]
        if missing:
            tmp_spec = AttackSpec(
                id=spec.id,
                name=spec.name,
                description=spec.description,
                image=spec.image,
                container_name=spec.container_name,
                params=missing,
                no_params_note=spec.no_params_note,
                details_warning=spec.details_warning,
                mitre=spec.mitre,
                tools=getattr(spec, "tools", None),
            )
            filled = prompt_params_interactive(tmp_spec)
            resolved.update(filled)

    resolved = coerce_params_types(spec, resolved)
    errs = validate_params(spec, resolved)
    if errs:
        for e in errs:
            print(f"- {e}", file=sys.stderr)
        _die("Parâmetros inválidos.")

    print("\n=== Execução ===")
    print_attack_details(spec)
    if spec.no_params_note and not spec.params:
        print(f"\nObs.: {spec.no_params_note}")
    if spec.params:
        print("\nParâmetros resolvidos:")
        for p in spec.params:
            print(f"- {p.key} = {resolved.get(p.key)}")

    result = run_attack(
        spec,
        resolved,
        capture_enabled=not args.no_capture,
        iface=args.iface,
        wait=not args.no_wait,
        capture_seconds=args.capture_seconds,
    )

    print("\n Resultado")
    cap = result.get("capture") or {}
    if cap.get("enabled"):
        print(f"PCAP: {cap.get('pcap_path')}")
        if cap.get("wait_error"):
            print(f"Obs.: {cap.get('wait_error')}")
    else:
        print("Captura: desativada")

    if result.get("ok"):
        _ok("Ataque iniciado/acionado.")
        if result.get("container_id"):
            print("Container ID:", result.get("container_id"))
    else:
        _die(result.get("stderr") or "Falha ao iniciar ataque.")

    print("Cmd:", " ".join(result.get("cmd", [])))

def cmd_servers_status(_args: argparse.Namespace) -> None:
    rows = get_servers_status_rows()
    print(_as_table(rows, headers=["Servidor", "IP"]))

def cmd_servers_start(_args: argparse.Namespace) -> None:
    servers_start_all()

def cmd_servers_stop(_args: argparse.Namespace) -> None:
    servers_stop_all()

def cmd_servers_restart(_args: argparse.Namespace) -> None:
    servers_stop_all()
    servers_start_all()

def cmd_servers_logs(args: argparse.Namespace) -> None:
    image = get_server_image_from_key(args.server)
    spec = SERVER_LOG_SPECS.get(image, {})
    is_binary = bool(spec.get("binary"))
    prefer_alt = bool(args.alt) or (is_binary and not args.raw)
    if is_binary and not args.alt and not args.raw:
        _warn(spec.get("binary_hint", "Log pode ser binário; usando modo alternativo."))
    res = fetch_server_logs(image, tail_lines=args.tail, prefer_alt=prefer_alt)
    print("Comando:")
    print(res.get("cmd_display", ""))
    print("\n--- stdout ---")
    print(res.get("stdout") or "(sem saída)")
    if res.get("stderr"):
        print("\n--- stderr ---", file=sys.stderr)
        print(res.get("stderr"), file=sys.stderr)

def cmd_clients_list(_args: argparse.Namespace) -> None:
    items = list_running_benign_clients()
    if not items:
        print("Nenhum cliente benigno em execução.")
        return
    rows = [{"Container": name, "N": n} for name, n in items]
    print(_as_table(rows, headers=["N", "Container"]))

def cmd_clients_start(_args: argparse.Namespace) -> None:
    start_one_benign_client()

def cmd_clients_stop_all(_args: argparse.Namespace) -> None:
    remove_all_benign_clients()

def cmd_captures_list(args: argparse.Namespace) -> None:
    captures_list(filter_substr=args.filter)

def cmd_captures_info(args: argparse.Namespace) -> None:
    p = _resolve_capture_path(args.pcap)
    captures_info(p)

def cmd_captures_export(args: argparse.Namespace) -> None:
    p = _resolve_capture_path(args.pcap)
    captures_export(p, Path(args.to))

def cmd_captures_features(args: argparse.Namespace) -> None:
    p = _resolve_capture_path(args.pcap)
    captures_extract_features(
        p,
        run_ntl=not args.no_ntl,
        run_tshark=not args.no_tshark,
        run_scapy=not args.no_scapy,
        overwrite=args.overwrite,
    )

def cmd_captures_view_features(args: argparse.Namespace) -> None:
    p = _resolve_capture_path(args.pcap)
    captures_view_features(p, tool=args.tool, rows=args.rows)

def cmd_captures_dataset(args: argparse.Namespace) -> None:
    p = _resolve_capture_path(args.pcap)
    captures_build_dataset(p)

def cmd_captures_view_dataset(args: argparse.Namespace) -> None:
    p = _resolve_capture_path(args.pcap)
    captures_view_dataset(p, rows=args.rows, cols=args.cols, search=args.search)

# -----------------------------
# Interface: modo interativo
# -----------------------------
def _pick_from_list(title: str, items: List[str]) -> Optional[str]:
    if not items:
        return None
    print(f"\n{title}")
    for i, it in enumerate(items, 1):
        print(f"{i:>2}) {it}")
    print(" 0) Voltar")
    while True:
        s = input("> ").strip()
        if not s.isdigit():
            continue
        n = int(s)
        if n == 0:
            return None
        if 1 <= n <= len(items):
            return items[n - 1]

def interactive_main() -> None:
    _ensure_dirs()
    while True:
        print("\n" + "=" * 60)
        print("SBRC26 — Testbed de Ataques (CLI)")
        print("=" * 60)
        print("Host IP:", get_host_ip())
        if docker_available():
            print("Docker: OK")
        else:
            print("Docker: INDISPONÍVEL")

        running_clients = list_running_benign_clients()
        print(f"Clientes benignos: {len(running_clients)}")

        print("\nMenu")
        print(" 1) Ataques")
        print(" 2) Servidores")
        print(" 3) Clientes benignos")
        print(" 4) Capturas / Features / Dataset")
        print(" 0) Sair")

        choice = input("> ").strip()
        if choice == "0":
            return
        if choice == "1":
            interactive_attacks()
        elif choice == "2":
            interactive_servers()
        elif choice == "3":
            interactive_clients()
        elif choice == "4":
            interactive_captures()

def interactive_attacks() -> None:
    cats = list(CATEGORIES.keys())
    cat = _pick_from_list("Categorias", cats)
    if not cat:
        return
    attacks = CATEGORIES[cat]
    labels = [f"{a.name}  (id={a.id})" for a in attacks]
    picked = _pick_from_list(cat, labels)
    if not picked:
        return
    attack_id = picked.split("id=", 1)[1].rstrip(")")
    spec = attack_by_id(attack_id)

    while True:
        print("\n" + "-" * 60)
        print_attack_details(spec)
        print("\nAções")
        print(" 1) Rodar ataque")
        print(" 2) Status")
        print(" 3) Parar")
        print(" 4) Logs (tail 200)")
        print(" 0) Voltar")
        c = input("> ").strip()
        if c == "0":
            return
        if c == "2":
            attack_status(spec)
            continue
        if c == "3":
            try:
                attack_stop(spec)
            except SystemExit:
                pass
            continue
        if c == "4":
            try:
                attack_show_logs(spec, tail=200)
            except SystemExit:
                pass
            continue
        if c == "1":
            resolved = prompt_params_interactive(spec)
            errs = validate_params(spec, resolved)
            if errs:
                print("\nParâmetros inválidos:")
                for e in errs:
                    print("-", e)
                continue

            cap_choice = input("Iniciar captura junto? [S/n] ").strip().lower()
            capture_enabled = (cap_choice != "n")
            iface = _prompt("Interface de captura", default="docker0")
            wait_choice = input("Aguardar término do container? [S/n] ").strip().lower()
            wait = (wait_choice != "n")
            capture_seconds = None
            if not wait and capture_enabled:
                s = input("Modo --no-wait: tempo de captura (s) [10]: ").strip()
                capture_seconds = int(s) if (s.isdigit()) else 10

            res = run_attack(
                spec,
                resolved,
                capture_enabled=capture_enabled,
                iface=iface,
                wait=wait,
                capture_seconds=capture_seconds,
            )
            print("\nResultado:")
            if res.get("ok"):
                print("- cmd:", " ".join(res.get("cmd", [])))
                cap = res.get("capture") or {}
                if cap.get("enabled"):
                    print("- pcap:", cap.get("pcap_path"))
                    if cap.get("wait_error"):
                        print("- obs:", cap.get("wait_error"))
            else:
                print("Falhou:", res.get("stderr"))

def interactive_servers() -> None:
    while True:
        print("\nServidores")
        print(" 1) Status")
        print(" 2) Iniciar")
        print(" 3) Parar")
        print(" 4) Reiniciar")
        print(" 5) Logs")
        print(" 0) Voltar")
        c = input("> ").strip()
        if c == "0":
            return
        if c == "1":
            print(_as_table(get_servers_status_rows(), headers=["Servidor", "IP"]))
        elif c == "2":
            try:
                servers_start_all()
            except SystemExit:
                pass
        elif c == "3":
            try:
                servers_stop_all()
            except SystemExit:
                pass
        elif c == "4":
            try:
                servers_stop_all()
                servers_start_all()
            except SystemExit:
                pass
        elif c == "5":
            keys = list(SERVER_KEY_TO_IMAGE.keys())
            picked = _pick_from_list("Escolha servidor (chave)", keys)
            if not picked:
                continue
            tail = input("Tail linhas [200]: ").strip()
            tail_n = int(tail) if tail.isdigit() else 200
            image = get_server_image_from_key(picked)
            spec = SERVER_LOG_SPECS.get(image, {})
            is_binary = bool(spec.get("binary"))
            prefer_alt = is_binary
            if is_binary:
                print(spec.get("binary_hint", "Log pode ser binário; usando modo alternativo."))
            res = fetch_server_logs(image, tail_lines=tail_n, prefer_alt=prefer_alt)
            print("\nComando:")
            print(res.get("cmd_display", ""))
            print("\n--- stdout ---")
            print(res.get("stdout") or "(sem saída)")
            if res.get("stderr"):
                print("\n--- stderr ---")
                print(res.get("stderr"))

def interactive_clients() -> None:
    while True:
        items = list_running_benign_clients()
        print("\nClientes benignos")
        print(f"Em execução: {len(items)}")
        print(" 1) Listar")
        print(" 2) Iniciar um")
        print(" 3) Remover todos")
        print(" 0) Voltar")
        c = input("> ").strip()
        if c == "0":
            return
        if c == "1":
            cmd_clients_list(argparse.Namespace())
        elif c == "2":
            try:
                start_one_benign_client()
            except SystemExit:
                pass
        elif c == "3":
            try:
                remove_all_benign_clients()
            except SystemExit:
                pass

def interactive_captures() -> None:
    while True:
        print("\nCapturas / Features / Dataset")
        print(" 1) Listar capturas")
        print(" 2) Info de captura")
        print(" 3) Extrair features")
        print(" 4) Ver features (prévia)")
        print(" 5) Gerar dataset")
        print(" 6) Ver dataset (prévia)")
        print(" 0) Voltar")
        c = input("> ").strip()
        if c == "0":
            return
        if c == "1":
            captures_list()
            continue

        name = input("Informe o PCAP (nome em captures/ ou caminho): ").strip()
        try:
            p = _resolve_capture_path(name)
        except SystemExit:
            continue

        if c == "2":
            captures_info(p)
        elif c == "3":
            overwrite = input("Sobrescrever CSVs existentes? [s/N] ").strip().lower() == "s"
            captures_extract_features(p, run_ntl=True, run_tshark=True, run_scapy=True, overwrite=overwrite)
        elif c == "4":
            tool = input("Tool (ntlflowlyzer|tshark|scapy) [tshark]: ").strip().lower() or "tshark"
            n = input("Linhas [50]: ").strip()
            captures_view_features(p, tool=tool, rows=int(n) if n.isdigit() else 50)
        elif c == "5":
            try:
                captures_build_dataset(p)
            except SystemExit:
                pass
        elif c == "6":
            n = input("Linhas [200]: ").strip()
            cols = input("Máx colunas [80]: ").strip()
            search = input("Filtro (substring, opcional): ").strip()
            captures_view_dataset(p, rows=int(n) if n.isdigit() else 200, cols=int(cols) if cols.isdigit() else 80, search=search)

# -----------------------------
# Parser
# -----------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ferramenta_cli.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(
            """\
            SBRC26 Testbed de Ataques — versão CLI.

            Exemplos:
              # listar ataques
              ./ferramenta_cli.py attack list

              # ver detalhes de um ataque
              ./ferramenta_cli.py attack info recon_arp_scan

              # rodar ataque (params via key=value)
              ./ferramenta_cli.py attack run recon_arp_scan --param target_net=172.17.0.0/16

              # status/logs/stop
              ./ferramenta_cli.py attack status recon_arp_scan
              ./ferramenta_cli.py attack logs recon_arp_scan --tail 200
              ./ferramenta_cli.py attack stop recon_arp_scan

              # servidores
              ./ferramenta_cli.py servers status
              ./ferramenta_cli.py servers restart
              ./ferramenta_cli.py servers logs ssh --tail 200

              # capturas
              ./ferramenta_cli.py captures list
              ./ferramenta_cli.py captures features <pcap>
              ./ferramenta_cli.py captures dataset <pcap>
              ./ferramenta_cli.py captures view-dataset <pcap> --rows 200 --cols 80 --search syn
            """
        ),
    )

    sub = p.add_subparsers(dest="cmd")

    # attacks
    a = sub.add_parser("attack", help="Operações de ataques")
    a_sub = a.add_subparsers(dest="attack_cmd", required=True)

    a_list = a_sub.add_parser("list", help="Lista ataques")
    a_list.set_defaults(func=cmd_attack_list)

    a_info = a_sub.add_parser("info", help="Mostra detalhes de um ataque")
    a_info.add_argument("attack_id")
    a_info.set_defaults(func=cmd_attack_info)

    a_run = a_sub.add_parser("run", help="Executa um ataque")
    a_run.add_argument("attack_id")
    a_run.add_argument("--param", action="append", help="Parâmetro no formato key=value (pode repetir)")
    a_run.add_argument("--interactive-params", action="store_true", help="Pergunta no terminal parâmetros faltantes")
    a_run.add_argument("--no-capture", action="store_true", help="Não iniciar tcpdump junto")
    a_run.add_argument("--iface", default="docker0", help="Interface de captura (default: docker0)")
    a_run.add_argument("--no-wait", action="store_true", help="Não aguardar término do container")
    a_run.add_argument("--capture-seconds", type=int, default=None, help="Quando --no-wait, duração de captura (s)")
    a_run.set_defaults(func=cmd_attack_run)

    a_status = a_sub.add_parser("status", help="Mostra status do container do ataque")
    a_status.add_argument("attack_id")
    a_status.set_defaults(func=cmd_attack_status)

    a_stop = a_sub.add_parser("stop", help="Remove o container do ataque")
    a_stop.add_argument("attack_id")
    a_stop.set_defaults(func=cmd_attack_stop)

    a_logs = a_sub.add_parser("logs", help="Logs do container do ataque")
    a_logs.add_argument("attack_id")
    a_logs.add_argument("--tail", type=int, default=200)
    a_logs.set_defaults(func=cmd_attack_logs)

    # servers
    s = sub.add_parser("servers", help="Operações dos servidores")
    s_sub = s.add_subparsers(dest="servers_cmd", required=True)

    s_status = s_sub.add_parser("status")
    s_status.set_defaults(func=cmd_servers_status)
    s_start = s_sub.add_parser("start")
    s_start.set_defaults(func=cmd_servers_start)
    s_stop = s_sub.add_parser("stop")
    s_stop.set_defaults(func=cmd_servers_stop)
    s_restart = s_sub.add_parser("restart")
    s_restart.set_defaults(func=cmd_servers_restart)
    s_logs = s_sub.add_parser("logs")
    s_logs.add_argument("server", help="Chave (web/ssh/smb/mqtt/coap/telnet/ssl) ou nome da imagem")
    s_logs.add_argument("--tail", type=int, default=200)
    s_logs.add_argument("--alt", action="store_true", help="Força modo alternativo (quando existir)")
    s_logs.add_argument("--raw", action="store_true", help="Força tail raw (mesmo se binário)")
    s_logs.set_defaults(func=cmd_servers_logs)

    # clients
    c = sub.add_parser("clients", help="Operações de clientes benignos")
    c_sub = c.add_subparsers(dest="clients_cmd", required=True)
    c_list = c_sub.add_parser("list")
    c_list.set_defaults(func=cmd_clients_list)
    c_start = c_sub.add_parser("start")
    c_start.set_defaults(func=cmd_clients_start)
    c_stop_all = c_sub.add_parser("stop-all")
    c_stop_all.set_defaults(func=cmd_clients_stop_all)

    # captures
    cap = sub.add_parser("captures", help="Operações sobre capturas/PCAP")
    cap_sub = cap.add_subparsers(dest="captures_cmd", required=True)
    cap_list = cap_sub.add_parser("list")
    cap_list.add_argument("--filter", default="", help="Filtrar por substring no nome")
    cap_list.set_defaults(func=cmd_captures_list)

    cap_info = cap_sub.add_parser("info")
    cap_info.add_argument("pcap")
    cap_info.set_defaults(func=cmd_captures_info)

    cap_export = cap_sub.add_parser("export")
    cap_export.add_argument("pcap")
    cap_export.add_argument("--to", required=True, help="Caminho destino (arquivo ou diretório)")
    cap_export.set_defaults(func=cmd_captures_export)

    cap_fx = cap_sub.add_parser("features", help="Extrai features para uma captura")
    cap_fx.add_argument("pcap")
    cap_fx.add_argument("--no-ntl", action="store_true", help="Não executar NTLFlowLyzer")
    cap_fx.add_argument("--no-tshark", action="store_true", help="Não executar TShark")
    cap_fx.add_argument("--no-scapy", action="store_true", help="Não executar Scapy")
    cap_fx.add_argument("--overwrite", action="store_true", help="Sobrescrever CSVs existentes")
    cap_fx.set_defaults(func=cmd_captures_features)

    cap_vfx = cap_sub.add_parser("view-features", help="Prévia de CSV de features")
    cap_vfx.add_argument("pcap")
    cap_vfx.add_argument("--tool", default="tshark", help="ntlflowlyzer|tshark|scapy")
    cap_vfx.add_argument("--rows", type=int, default=50)
    cap_vfx.set_defaults(func=cmd_captures_view_features)

    cap_ds = cap_sub.add_parser("dataset", help="Gera dataset unsupervised para uma captura")
    cap_ds.add_argument("pcap")
    cap_ds.set_defaults(func=cmd_captures_dataset)

    cap_vds = cap_sub.add_parser("view-dataset", help="Prévia do dataset")
    cap_vds.add_argument("pcap")
    cap_vds.add_argument("--rows", type=int, default=200)
    cap_vds.add_argument("--cols", type=int, default=80)
    cap_vds.add_argument("--search", default="")
    cap_vds.set_defaults(func=cmd_captures_view_dataset)

    return p

def main(argv: Optional[List[str]] = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        interactive_main()
        return
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)

if __name__ == "__main__":
    main()
