# modules/features.py
from __future__ import annotations

import csv
import re
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Tuple

FEATURES_DIR = Path("features")
TMP_DIR = Path(".tmp")

def _ensure_dirs() -> None:
    """
    Garante existência do diretório de saída
    """
    FEATURES_DIR.mkdir(parents=True, exist_ok=True)
    TMP_DIR.mkdir(parents=True, exist_ok=True)

def stem_no_ext(p: Path) -> str:
    """
    Camiho do arquivo de captura em string

    :param p: Camiho do arquivo de captura como path
    :type p: Path
    :return: Camiho do arquivo de captura em string
    :rtype: str
    """
    return p.name[:-5] if p.name.lower().endswith(".pcap") else p.stem

def tool_exists(exe: str) -> bool:
    """
    Verifica se a ferramenta que será usada existe

    :param exe: Ferramenta para testar
    :type exe: str
    :return: Retorna true ou false
    :rtype: bool
    """
    return shutil.which(exe) is not None

def _run(cmd: List[str]) -> Tuple[int, str, str]:
    """
    binary-safe

    :param cmd: Comando para execução
    :type cmd: List[str]
    :return: Comando completo com parâmetros
    :rtype: Tuple[int, str, str]
    """
    p = subprocess.run(cmd, capture_output=True)
    stdout = (p.stdout or b"").decode("utf-8", errors="replace").strip()
    stderr = (p.stderr or b"").decode("utf-8", errors="replace").strip()
    return p.returncode, stdout, stderr

_TRUNC_PCAP_PATTERNS = (
    "unpack requires a buffer of 16 bytes",
    "dpkt.dpkt.needdata",
    "got 15, 16 needed",
    "needdata: got",
)

def looks_like_truncated_pcap(stderr: str) -> bool:
    s = (stderr or "").lower()
    return any(p in s for p in _TRUNC_PCAP_PATTERNS)

def sanitize_pcap_for_tools(pcap_path: Path) -> Path:
    """
    Regrava o PCAP para descartar caudas truncadas/corrompidas.
    Preferência: tshark; fallback: editcap.
    Retorna o caminho do PCAP sanitizado (ou o original se não der).

    :param pcap_path: Caminho do arquivo pcap
    :type pcap_path: Path
    :return: Caminho do pcap sanitizado
    :rtype: Path
    """
    _ensure_dirs()
    cleaned = TMP_DIR / f"clean-{stem_no_ext(pcap_path)}.pcap"

    try:
        if cleaned.exists() and cleaned.stat().st_mtime >= pcap_path.stat().st_mtime:
            return cleaned
    except Exception:
        pass

    if tool_exists("tshark"):
        cmd = ["tshark", "-r", str(pcap_path), "-w", str(cleaned), "-F", "pcap"]
        p = subprocess.run(cmd, capture_output=True)
        if p.returncode == 0 and cleaned.exists() and cleaned.stat().st_size > 24:
            return cleaned

    if tool_exists("editcap"):
        cmd = ["editcap", "-F", "pcap", str(pcap_path), str(cleaned)]
        p = subprocess.run(cmd, capture_output=True)
        if p.returncode == 0 and cleaned.exists() and cleaned.stat().st_size > 24:
            return cleaned

    return pcap_path

def build_feature_paths(pcap_path: Path, features_dir: Path = FEATURES_DIR) -> Dict[str, Path]:
    """
    Define caminhos completos de saída da extração de features

    :param pcap_path: Caminho do arquivo de captura
    :type pcap_path: Path
    :param features_dir: Caminho do diretório de features, padrão é features/
    :type features_dir: Path, optional
    :return: Caminho do arquivo de saída, por ferramenta
    :rtype: Dict[str, Path]
    """
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
    """
    Extração com o NTLFlowLyzer

    :param pcap_path: Caminho do arquivo de captura
    :type pcap_path: Path
    :param out_csv: Caminho do arquivo de saída csv
    :type out_csv: Path
    :return: Caminho do arquivo de saída, por ferramenta
    :rtype: Dict[str, Any]
    """
    if not tool_exists("ntlflowlyzer"):
        return {"ok": False, "stderr": "ntlflowlyzer não encontrado no PATH (instale o NTLFlowLyzer).", "cmd": []}

    _ensure_dirs()

    def _run_ntl(pcap_in: Path) -> Tuple[int, str, str, Path]:
        cfg = {
            "pcap_file_address": str(pcap_in.resolve()),
            "output_file_address": str(out_csv.resolve()),
            "label": "Unknown",
            "number_of_threads": 6,
        }

        cfg_path = TMP_DIR / f"ntlflowlyzer-{stem_no_ext(pcap_in)}.json"
        cfg_path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")

        cmd = ["ntlflowlyzer", "-c", str(cfg_path)]
        rc, out, err = _run(cmd)
        return rc, out, err, cfg_path

    # 1ª tentativa: PCAP original
    rc, out, err, cfg_path = _run_ntl(pcap_path)

    # Se parece PCAP truncado, tenta regravar e rodar de novo
    used_pcap = pcap_path
    retried = False
    if rc != 0 and looks_like_truncated_pcap(err):
        cleaned = sanitize_pcap_for_tools(pcap_path)
        if cleaned != pcap_path:
            retried = True
            used_pcap = cleaned
            rc, out, err, cfg_path = _run_ntl(cleaned)

    ok = (rc == 0) and out_csv.exists()

    user_hint = ""
    if not ok and looks_like_truncated_pcap(err):
        user_hint = (
            "Falha no NTLFlowLyzer: a captura parece truncada/corrompida (PCAP incompleto). "
            "Tente recapturar encerrando o tcpdump de forma graciosa (SIGINT/TERM) e aguardando o flush."
        )
        if retried:
            user_hint += " Foi tentada uma sanitização automática do PCAP antes de reexecutar."

    return {
        "ok": ok,
        "returncode": rc,
        "stdout": out,
        "stderr": err,
        "cmd": ["ntlflowlyzer", "-c", str(cfg_path)],
        "output": str(out_csv),
        "config": str(cfg_path),
        "pcap_used": str(used_pcap),
        "retried_with_sanitized_pcap": retried,
        "hint": user_hint,
    }

# TShark
def extract_with_tshark(pcap_path: Path, out_csv: Path) -> Dict[str, Any]:
    """
    Extração com o TShark

    :param pcap_path: Caminho do arquivo de captura
    :type pcap_path: Path
    :param out_csv: Caminho do arquivo de saída csv
    :type out_csv: Path
    :return: Caminho do arquivo de saída, por ferramenta
    :rtype: Dict[str, Any]
    """
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
    """
    Extração com o Scapy

    :param pcap_path: Caminho do arquivo de captura
    :type pcap_path: Path
    :param out_csv: Caminho do arquivo de saída csv
    :type out_csv: Path
    :return: Caminho do arquivo de saída, por ferramenta
    :rtype: Dict[str, Any]
    """
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
