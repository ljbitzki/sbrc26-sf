# datasets.py
from __future__ import annotations
from pathlib import Path
from datetime import datetime
from typing import Iterable, Union, List
import pandas as pd

PathLike = Union[str, Path]
def _ensure_dir(path: PathLike) -> Path:
    """
    Garante existência do diretório de saída

    :param path: Caminho relativo
    :type path: PathLike
    :return: Caminho absoluto para verificação e criação, se necessário
    :rtype: Path
    """
    p = Path(path)
    if p.suffix:
        p.parent.mkdir(parents=True, exist_ok=True)
    else:
        p.mkdir(parents=True, exist_ok=True)
    return p

def _detect_source_tool(df: pd.DataFrame, path: Path) -> str:
    """
    

    :param df: Dataframes pandas
    :type df: pd.DataFrame
    :param path: Caminho dos dataframes
    :type path: Path
    :return: Retorna provavel nome dos arquivos
    :rtype: str
    """
    name = path.name.lower()

    # NTLFlowLyzer (flow-level)
    if "ntlflowlyzer-" in name or "flow_id" in df.columns or "packets_IAT_mean" in df.columns:
        return "ntlflowlyzer"

    # TShark (packet-level) - conforme seu extractor atual
    if "tshark-" in name and "frame.number" in df.columns and "frame.time_epoch" in df.columns:
        return "tshark_packets"

    # Scapy (packet-level) - conforme seu extractor atual
    if "scapy-" in name and "pkt_index" in df.columns and "time_epoch" in df.columns:
        return "scapy_packets"

    return "unknown"

def _normalize_ntlflowlyzer(df: pd.DataFrame) -> pd.DataFrame:
    """
    Normalização NTLFlowLyzer       

    :param df: Dataframe pandas
    :type df: pd.DataFrame
    :return: Novo dataframe "normalizado"
    :rtype: pd.DataFrame
    """
    df = df.copy()

    # padroniza nomes mínimos
    rename_map = {
        "protocol": "proto",
        "duration": "dur",
        "packets_count": "pkts",
    }
    df = df.rename(columns=rename_map)

    # bytes = payload + header
    if "total_payload_bytes" in df.columns and "total_header_bytes" in df.columns:
        df["bytes"] = pd.to_numeric(df["total_payload_bytes"], errors="coerce").fillna(0) + \
                      pd.to_numeric(df["total_header_bytes"], errors="coerce").fillna(0)

    # timestamp mínimo
    if "timestamp" in df.columns:
        df["ts"] = pd.to_numeric(df["timestamp"], errors="coerce")
    else:
        df["ts"] = pd.NA

    # renomear label interno para evitar rotulamento neste momento
    if "label" in df.columns:
        df = df.rename(columns={"label": "ntlflow_label"})

    # garante tipos mínimos
    for col in ["src_port", "dst_port", "proto", "dur", "pkts", "bytes", "ts"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    return df

def _normalize_tshark_packets(df: pd.DataFrame) -> pd.DataFrame:
    """
    Normalização TShark       

    :param df: Dataframe pandas
    :type df: pd.DataFrame
    :return: Novo dataframe "normalizado"
    :rtype: pd.DataFrame
    """
    df = df.copy()

    # Campos do extrator:
    # frame.time_epoch, frame.len, ip.src, ip.dst, ip.proto, tcp.srcport, tcp.dstport, udp.srcport, udp.dstport
    df["ts"] = pd.to_numeric(df.get("frame.time_epoch"), errors="coerce")
    df["bytes"] = pd.to_numeric(df.get("frame.len"), errors="coerce")

    df["src_ip"] = df.get("ip.src")
    df["dst_ip"] = df.get("ip.dst")
    df["proto"] = pd.to_numeric(df.get("ip.proto"), errors="coerce")

    # porta: tenta TCP, depois UDP
    df["src_port"] = pd.to_numeric(df.get("tcp.srcport"), errors="coerce")
    df["dst_port"] = pd.to_numeric(df.get("tcp.dstport"), errors="coerce")

    df["src_port"] = df["src_port"].fillna(pd.to_numeric(df.get("udp.srcport"), errors="coerce"))
    df["dst_port"] = df["dst_port"].fillna(pd.to_numeric(df.get("udp.dstport"), errors="coerce"))

    # packet-level => pkts = 1
    df["pkts"] = 1

    return df

def _normalize_scapy_packets(df: pd.DataFrame) -> pd.DataFrame:
    """
    Normalização Scapy

    :param df: Dataframe pandas
    :type df: pd.DataFrame
    :return: Novo dataframe "normalizado"
    :rtype: pd.DataFrame
    """
    df = df.copy()

    # Campos do extrator:
    # time_epoch, frame_len, ip_src, ip_dst, ip_proto, src_port, dst_port
    
    df["ts"] = pd.to_numeric(df.get("time_epoch"), errors="coerce")
    df["bytes"] = pd.to_numeric(df.get("frame_len"), errors="coerce")
    df["src_ip"] = df.get("ip_src")
    df["dst_ip"] = df.get("ip_dst")
    df["proto"] = pd.to_numeric(df.get("ip_proto"), errors="coerce")
    df["src_port"] = pd.to_numeric(df.get("src_port"), errors="coerce")
    df["dst_port"] = pd.to_numeric(df.get("dst_port"), errors="coerce")

    df["pkts"] = 1
    return df

def _normalize_common(df: pd.DataFrame, source: str) -> pd.DataFrame:
    """
    Normalização generalista

    :param df: Dataframne
    :type df: pd.DataFrame
    :param source: Origem do dataframe
    :type source: str
    :return: Dataframe normalizado
    :rtype: pd.DataFrame
    """
    if source == "ntlflowlyzer":
        df = _normalize_ntlflowlyzer(df)
    elif source == "tshark_packets":
        df = _normalize_tshark_packets(df)
    elif source == "scapy_packets":
        df = _normalize_scapy_packets(df)
    else:
        df = df.copy()
        df["ts"] = pd.NA
        df["bytes"] = pd.NA
        df["pkts"] = pd.NA

    df["source_tool"] = source
    return df

def load_features(csv_paths: Union[PathLike, Iterable[PathLike]]) -> pd.DataFrame:
    """
    Carrega features

    :param csv_paths: Caminhos dos arquivos csv
    :type csv_paths: Union[PathLike, Iterable[PathLike]]
    :raises FileNotFoundError: Erro caso o arquivo não seja encontrado
    :raises ValueError: Erro caso o arquivo não possua valores que dê para trabalhar
    :return: Dataframe
    :rtype: pd.DataFrame
    """
    if isinstance(csv_paths, (str, Path)):
        csv_paths = [csv_paths]

    dfs: List[pd.DataFrame] = []
    for path in csv_paths:
        p = Path(path)
        if not p.is_file():
            raise FileNotFoundError(f"Arquivo CSV não encontrado: {p}")

        df = pd.read_csv(p, engine="python")
        source = _detect_source_tool(df, p)

        df_norm = _normalize_common(df, source)
        df_norm["__source_csv"] = p.name
        dfs.append(df_norm)

    if not dfs:
        raise ValueError("Nenhum valor fornecido.")

    return pd.concat(dfs, ignore_index=True)

def build_dataset_unsupervised_for_capture(
    capture_pcap: PathLike,
    *,
    features_dir: PathLike = "features",
    outdir: PathLike = "datasets",
    save: bool = True,
) -> Path:
    """
    Monta o dataset não supervisionado referente a UMA captura.
    Procura automaticamente ntlflowlyzer-<base>.csv, tshark-<base>.csv, scapy-<base>.csv.
    Salva datasets/unsupervised-<base>.csv

    :param capture_pcap: Arquivo de captura
    :type capture_pcap: PathLike
    :param features_dir: Diretório das features, padrão é "features/"
    :type features_dir: PathLike, optional
    :param outdir: Diretório dos datasets, padrão é "datasets/"
    :type outdir: PathLike, optional
    :param save: Booleano para salvar em arquivo ou não, padrão é True
    :type save: bool, optional
    :raises FileNotFoundError: Erro caso o arquivo não seja encontrado
    :return: Caminho completo do salvamento do dataset
    :rtype: Path
    """
    capture_pcap = Path(capture_pcap)
    base = capture_pcap.name[:-5] if capture_pcap.name.lower().endswith(".pcap") else capture_pcap.stem

    feats_dir = Path(features_dir)
    candidates = [
        feats_dir / f"ntlflowlyzer-{base}.csv",
        feats_dir / f"tshark-{base}.csv",
        feats_dir / f"scapy-{base}.csv",
    ]
    csvs = [p for p in candidates if p.exists()]
    if not csvs:
        raise FileNotFoundError(f"Nenhum CSV de features encontrado para {base} em {feats_dir}")

    df = load_features(csvs)

    if save:
        _ensure_dir(outdir)
        out_path = Path(outdir) / f"unsupervised-{base}.csv"
        df.to_csv(out_path, index=False)
        return out_path

    return Path(outdir) / f"unsupervised-{base}.csv"
