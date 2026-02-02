# modules/features.py
from __future__ import annotations

import csv
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Diretórios padrão (mesmos da ferramenta principal)
FEATURES_DIR = Path("features")
TMP_DIR = Path(".tmp")


def _ensure_dirs() -> None:
    FEATURES_DIR.mkdir(parents=True, exist_ok=True)
    TMP_DIR.mkdir(parents=True, exist_ok=True)


def stem_no_ext(p: Path) -> str:
    return p.name[:-5] if p.name.lower().endswith(".pcap") else p.stem


def tool_exists(exe: str) -> bool:
    return shutil.which(exe) is not None


def _run(cmd: List[str]) -> Tuple[int, str, str]:
    """
    binary-safe.
    """
    p = subprocess.run(cmd, capture_output=True)
    stdout = (p.stdout or b"").decode("utf-8", errors="replace").strip()
    stderr = (p.stderr or b"").decode("utf-8", errors="replace").strip()
    return p.returncode, stdout, stderr


def build_feature_paths(pcap_path: Path, features_dir: Path = FEATURES_DIR) -> Dict[str, Path]:
    base = stem_no_ext(pcap_path)
    return {
        "ntlflowlyzer": features_dir / f"ntlflowlyzer-{base}.csv",
        "tshark": features_dir / f"tshark-{base}.csv",
        "scapy": features_dir / f"scapy-{base}.csv",
    }

# -----------------------------
# Extração de Features
# -----------------------------

# NTLFlowLyzer
def extract_with_ntlflowlyzer(pcap_path: Path, out_csv: Path) -> Dict[str, Any]:
    if not tool_exists("ntlflowlyzer"):
        return {"ok": False, "stderr": "ntlflowlyzer não encontrado no PATH (instale o NTLFlowLyzer).", "cmd": []}

    _ensure_dirs()

    cfg = {
        "pcap_file_address": str(pcap_path.resolve()),
        "output_file_address": str(out_csv.resolve()),
        "label": "Unknown",
        "number_of_threads": 4,
    }

    cfg_path = TMP_DIR / f"ntlflowlyzer-{stem_no_ext(pcap_path)}.json"
    cfg_path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")

    cmd = ["ntlflowlyzer", "-c", str(cfg_path)]
    rc, out, err = _run(cmd)

    ok = (rc == 0) and out_csv.exists()  # pode ser vazio

    return {
        "ok": ok,
        "returncode": rc,
        "stdout": out,
        "stderr": err,
        "cmd": cmd,
        "output": str(out_csv),
        "config": str(cfg_path),
    }

# TShark
def extract_with_tshark(pcap_path: Path, out_csv: Path) -> Dict[str, Any]:
    if not tool_exists("tshark"):
        return {"ok": False, "stderr": "tshark não encontrado no PATH.", "cmd": []}

    _ensure_dirs()

    fields = [
        "frame.number",
        "frame.time_epoch",
        "frame.len",
        "_ws.col.Protocol",
        "eth.src",
        "eth.dst",
        "ip.src",
        "ip.dst",
        "ip.proto",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.flags",
        "udp.srcport",
        "udp.dstport",
    ]

    cmd = [
        "tshark",
        "-r",
        str(pcap_path),
        "-T",
        "fields",
        "-E",
        "header=y",
        "-E",
        "separator=,",
        "-E",
        "quote=d",
        "-E",
        "occurrence=f",
    ]
    for f in fields:
        cmd += ["-e", f]

    try:
        p = subprocess.run(cmd, capture_output=True)
        stdout = (p.stdout or b"").decode("utf-8", errors="replace")
        stderr = (p.stderr or b"").decode("utf-8", errors="replace").strip()

        out_csv.write_text(stdout, encoding="utf-8")
        ok = (p.returncode == 0) and out_csv.exists()
        return {"ok": ok, "returncode": p.returncode, "stderr": stderr, "cmd": cmd, "output": str(out_csv)}
    except Exception as e:
        return {"ok": False, "stderr": str(e), "cmd": cmd}

# Python Scapy
def extract_with_scapy(pcap_path: Path, out_csv: Path) -> Dict[str, Any]:
    _ensure_dirs()
    try:
        from scapy.all import PcapReader  # type: ignore
        from scapy.layers.inet import IP, TCP, UDP  # type: ignore
        from scapy.layers.l2 import Ether  # type: ignore
    except Exception as e:
        return {"ok": False, "stderr": f"Scapy não disponível/import falhou: {e}", "cmd": ["python/scapy"]}

    header = [
        "pkt_index",
        "time_epoch",
        "frame_len",
        "eth_src",
        "eth_dst",
        "ip_src",
        "ip_dst",
        "ip_proto",
        "l4",
        "src_port",
        "dst_port",
        "tcp_flags",
    ]

    try:
        with out_csv.open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(header)

            idx = 0
            with PcapReader(str(pcap_path)) as pr:
                for pkt in pr:
                    idx += 1
                    t = getattr(pkt, "time", None)

                    eth_src = eth_dst = ""
                    ip_src = ip_dst = ""
                    ip_proto = ""
                    l4 = ""
                    src_port = dst_port = ""
                    tcp_flags = ""

                    frame_len = len(bytes(pkt))

                    if pkt.haslayer(Ether):
                        eth = pkt[Ether]
                        eth_src = getattr(eth, "src", "") or ""
                        eth_dst = getattr(eth, "dst", "") or ""

                    if pkt.haslayer(IP):
                        ip = pkt[IP]
                        ip_src = getattr(ip, "src", "") or ""
                        ip_dst = getattr(ip, "dst", "") or ""
                        ip_proto = str(getattr(ip, "proto", "") or "")

                        if pkt.haslayer(TCP):
                            tcp = pkt[TCP]
                            l4 = "TCP"
                            src_port = str(getattr(tcp, "sport", "") or "")
                            dst_port = str(getattr(tcp, "dport", "") or "")
                            tcp_flags = str(getattr(tcp, "flags", "") or "")
                        elif pkt.haslayer(UDP):
                            udp = pkt[UDP]
                            l4 = "UDP"
                            src_port = str(getattr(udp, "sport", "") or "")
                            dst_port = str(getattr(udp, "dport", "") or "")

                    w.writerow(
                        [
                            idx,
                            f"{float(t):.6f}" if t is not None else "",
                            frame_len,
                            eth_src,
                            eth_dst,
                            ip_src,
                            ip_dst,
                            ip_proto,
                            l4,
                            src_port,
                            dst_port,
                            tcp_flags,
                        ]
                    )

        return {"ok": True, "cmd": ["python/scapy"], "output": str(out_csv)}
    except Exception as e:
        return {"ok": False, "stderr": str(e), "cmd": ["python/scapy"], "output": str(out_csv)}
