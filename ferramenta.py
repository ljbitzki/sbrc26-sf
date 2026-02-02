import csv
import ipaddress
import json
import shutil
import signal
import socket
import subprocess
import time
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Union, Optional, Tuple
import streamlit as st
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
FEATURES_DIR = Path("features")
DATASETS_DIR = Path("datasets")
TMP_DIR = Path(".tmp")

def build_dataset_path_for_capture(pcap_path: Path) -> Path:
    """
    Linka capturas a futuras gerações de dataset (mesma linha)

    :param pcap_path: Caminho do arquivop .pcap
    :type pcap_path: Path
    :return: Caminho completo do arquivo de dataset
    :rtype: Path
    """
    base = stem_no_ext(pcap_path)
    DATASETS_DIR.mkdir(parents=True, exist_ok=True)
    return DATASETS_DIR / f"unsupervised-{base}.csv"

def _ensure_dirs() -> None:
    """
    Garante diretórtios de saída
    """
    CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
    FEATURES_DIR.mkdir(parents=True, exist_ok=True)
    TMP_DIR.mkdir(parents=True, exist_ok=True)


def stem_no_ext(p: Path) -> str:
    """
    Exemplo recon_arp_scan-20260124_161958 (sem .pcap)

    :param p: Arquivo .pcap sem extensão
    :type p: Path
    :return: Caminho completo do arquivo .pcap sem extensão
    :rtype: str
    """
    return p.name[:-5] if p.name.lower().endswith(".pcap") else p.stem

def build_feature_paths(pcap_path: Path) -> Dict[str, Path]:
    """
    Linka capturas a futuras extraçõpes de features (mesma linha)

    :param pcap_path: Caminho completo do arquivo pcap para relacionar com futura extração
    :type pcap_path: Path
    :return: Dicionário de caminhos para as ferramentas de extração
    :rtype: Dict[str, Path]
    """
    base = stem_no_ext(pcap_path)
    return {
        "ntlflowlyzer": FEATURES_DIR / f"ntlflowlyzer-{base}.csv",
        "tshark": FEATURES_DIR / f"tshark-{base}.csv",
        "scapy": FEATURES_DIR / f"scapy-{base}.csv",
    }

def build_capture_path(attack_id: str) -> Path:
    """
    Padroniza saída de capturas

    :param attack_id: ID do ataque vindo do arquivo de registry
    :type attack_id: str
    :return: Caminho completo do arquivo de pcap para salvamento
    :rtype: Path
    """
    _ensure_dirs()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return CAPTURES_DIR / f"{attack_id}-{ts}.pcap"

def tool_exists(exe: str) -> bool:
    """
    Testa se ferramentas existem quando são chamadas para evitar quebrar a execução

    :param exe: Nome do binário para teste
    :type exe: str
    :return: Retorna true ou false para a existência da ferramenta
    :rtype: bool
    """
    return shutil.which(exe) is not None

# -----------------------------
# Execução de comandos (binary-safe)
# -----------------------------
def _run(cmd: List[str]) -> Tuple[int, str, str]:
    """
    Executa comando e retorna (rc, stdout, stderr) SEM UnicodeDecodeError.
    Decodifica bytes com UTF-8 errors='replace'.

    :param cmd: Comando para execução
    :type cmd: List[str]
    :return: Saídas padrão
    :rtype: Tuple[int, str, str]
    """
    p = subprocess.run(cmd, capture_output=True)  # bytes
    stdout = (p.stdout or b"").decode("utf-8", errors="replace").strip()
    stderr = (p.stderr or b"").decode("utf-8", errors="replace").strip()
    return p.returncode, stdout, stderr

# Definições para o spawn de clientes benignos
CLIENT_NAME_RE = re.compile(r"^sbrc26-cliente-(\d{1,2})$")
CLIENT_IMAGE = "sbrc26-clientes:latest"
CLIENT_NAME_PREFIX = "sbrc26-cliente-"
CLIENT_MAX_RUNNING = 10

def list_running_benign_clients() -> List[Tuple[str, int]]:
    """
    Retorna lista [(container_name, n)] apenas de containers RUNNING cujo nome
    casa com sbrc26-cliente-x.

    :return: Lista de containers de clientes benignos que estão rodando
    :rtype: List[Tuple[str, int]]
    """
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
    # ordena lista simples por número
    items.sort(key=lambda x: x[1])
    return items

def next_benign_client_number(running_clients: List[Tuple[str, int]]) -> int:
    """
    Próximo número = (maior número em execução) + 1.
    Se não houver nenhum, começa em 1.

    :param running_clients: Lista de containers de clientes benignos que estão rodando
    :type running_clients: List[Tuple[str, int]]
    :return: Retorna número do próximo cliente benigno
    :rtype: int
    """
    if not running_clients:
        return 1
    return max(n for _, n in running_clients) + 1

def remove_all_benign_clients(running_clients: List[Tuple[str, int]]) -> dict:
    """
    docker rm -f em todos os containers em execução que batem com o prefixo.
    :param running_clients: Lista de containers de clientes benignos que estão rodando
    :type running_clients: List[Tuple[str, int]]
    :return: Status da execução
    :rtype: dict
    """
    if not docker_available():
        return {"ok": False, "stderr": "Docker indisponível.", "cmd": []}

    if not running_clients:
        return {"ok": True, "stdout": "Nenhum cliente para remover.", "cmd": []}

    names = [name for name, _ in running_clients]
    cmd = ["docker", "rm", "-f", *names]
    rc, out, err = _run(cmd)
    return {"ok": rc == 0, "stdout": out, "stderr": err, "cmd": cmd, "returncode": rc}


def start_one_benign_client(running_clients: List[Tuple[str, int]]) -> dict:
    """
    Spawna um cliente benigno por clique do botão, até 10
    docker run -d --rm --name sbrc26-cliente-Y sbrc26-clientes:latest "<HOST_IP>"
    habilitar apenas se count < 10 e se todos os 7 servidores estiverem rodando.

    :param running_clients: Lista de containers de clientes benignos que estão rodando
    :type running_clients: List[Tuple[str, int]]
    :return: Discionário de parâmetros dos containers de clientes benignos que estão rodando
    :rtype: dict
    """
    if not docker_available():
        return {"ok": False, "stderr": "Docker indisponível.", "cmd": []}

    if len(running_clients) >= CLIENT_MAX_RUNNING:
        return {"ok": False, "stderr": "Limite de 10 clientes benignos já atingido.", "cmd": []}

    server_ips, missing = get_required_server_ips()
    if not server_ips:
        return {
            "ok": False,
            "stderr": f"Não é possível iniciar cliente: servidor(es) não estão rodando/sem IP: {', '.join(missing)}",
            "cmd": [],
        }

    y = next_benign_client_number(running_clients)
    name = f"{CLIENT_NAME_PREFIX}{y}"

    # 7 argumentos na ordem definida
    cmd = ["docker", "run", "-d", "--rm", "--name", name, CLIENT_IMAGE, *server_ips]
    rc, out, err = _run(cmd)

    return {
        "ok": rc == 0,
        "stdout": out,
        "stderr": err,
        "cmd": cmd,
        "returncode": rc,
        "container_name": name,
        "server_ips": server_ips,
    }

# -----------------------------
# Sidebar: Servidores + Logs
# -----------------------------

# Especificações dos servidores para exibir na barra lateral
SERVER_SPECS = [
    ("Web Server", "sbrc26-servidor-http-server"),
    ("SSH Server", "sbrc26-servidor-ssh-server"),
    ("SMB Server", "sbrc26-servidor-smb-server"),
    ("MQTT Broker", "sbrc26-servidor-mqtt-broker"),
    ("CoAP Server", "sbrc26-servidor-coap-server"),
    ("Telnet Server", "sbrc26-servidor-telnet-server"),
    ("SSL Heartbleed", "sbrc26-servidor-ssl-heartbleed"),
]

BENIGN_CLIENT_SERVER_ORDER = [
    ("WEB",    "sbrc26-servidor-http-server"),
    ("SSH",    "sbrc26-servidor-ssh-server"),
    ("SMB",    "sbrc26-servidor-smb-server"),
    ("MQTT",   "sbrc26-servidor-mqtt-broker"),
    ("COAP",   "sbrc26-servidor-coap-server"),
    ("TELNET", "sbrc26-servidor-telnet-server"),
    ("SSL",    "sbrc26-servidor-ssl-heartbleed"),
]

# Especificações dos logs dos servidores
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

# -----------------------------
# Configuração da página
# -----------------------------
st.set_page_config(page_title="Testbed de Ataques (Streamlit)", layout="wide")
st.title("Testbed de Ataques")
st.caption(
    "Selecione uma categoria e um ataque. Preencha os parâmetros (quando aplicável) "
    "e clique em Iniciar ataque para acionar a execução via Docker."
)

# Tentativa de deixar mais agradável o impilhamento de funcionalidades na tela
st.markdown(
    '''
    <style>
    section[data-testid="stSidebar"] button[kind="secondary"],
    section[data-testid="stSidebar"] button[kind="primary"] {
        padding-top: 0.15rem !important;
        padding-bottom: 0.15rem !important;
        min-height: 1.6rem !important;
        line-height: 1.2rem !important;
        font-size: 0.85rem !important;
    }
    section[data-testid="stSidebar"] .stButton {
        margin-bottom: 0.2rem !important;
    }
    </style>
    ''',
    unsafe_allow_html=True,
)

# Estado persistente do output do último ataque
if "last_attack_result" not in st.session_state:
    st.session_state["last_attack_result"] = {}
if "view" not in st.session_state:
    st.session_state["view"] = "main"

# -----------------------------
# Docker helpers (inspect/list)
# -----------------------------

_MITRE_PATH_RE = re.compile(
    r"/(?P<kind>techniques|tactics)/(?P<id>[^/?#]+(?:/[^/?#]+)?)",
    re.IGNORECASE,
)

def normalize_mitre(mitre: Optional[Union[str, List[str]]]) -> List[str]:
    """
    Normalização dos links de referência do MITRE ATT&CK

    :param mitre: Descrição da técnica
    :type mitre: Optional[Union[str, List[str]]]
    :return: Lista de técnicas
    :rtype: List[str]
    """
    if not mitre:
        return []
    if isinstance(mitre, str):
        return [mitre]
    return [m for m in mitre if isinstance(m, str) and m.strip()]

def mitre_label_from_url(url: str) -> str:
    """
    Extrai label após 'techniques/' ou 'tactics/'.
    Ex.:
      .../techniques/T1595/003/ -> T1595/003
      .../techniques/T1018/     -> T1018
      .../tactics/TA0007/       -> TA0007
    """
    m = _MITRE_PATH_RE.search(url)
    if not m:
        return url.rstrip("/")

    label = m.group("id").rstrip("/")
    return label

def render_mitre_links(mitre: Optional[Union[str, List[str]]]) -> None:
    """
    Retorna lista de URLs

    :param mitre: Lista de URLs
    :type mitre: Optional[Union[str, List[str]]]
    """
    urls = normalize_mitre(mitre)
    if not urls:
        return

    parts = []
    for u in urls:
        label = mitre_label_from_url(u)
        parts.append(f'<a href="{u}" target="_blank"><code>{label}</code></a>')

    st.markdown("Categorias MITRE ATT&CK: " + " ".join(parts), unsafe_allow_html=True)

def normalize_tools(tools: Optional[List[Dict[str, str]]]) -> List[Dict[str, str]]:
    """
    Aceita dois formatos:
    [{"name": "Python", "url": "https://..."}]
    [{"Python": "https://..."}, {"Streamlit": "https://..."}]
    Normaliza para lista de {"name":..., "url":...}

    :param tools: Retorna nome da ferramenta e URL
    :type tools: Optional[List[Dict[str, str]]]
    :return: Informações em formato esperado pelo render
    :rtype: List[Dict[str, str]]
    """
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
            continue
    return norm

def render_tools_links(tools: Optional[List[Dict[str, str]]]) -> None:
    """
    Renderiza nomes das ferramentas registradas nas especificações

    :param tools: Lista de dicionários Nome : URL
    :type tools: Optional[List[Dict[str, str]]]
    """
    items = normalize_tools(tools)
    if not items:
        return

    parts = []
    for it in items:
        name = it["name"]
        url = it["url"]
        parts.append(f'<a href="{url}" target="_blank"><code>{name}</code></a>')

    st.markdown("Ferramentas: " + " ".join(parts), unsafe_allow_html=True)

def _container_ids_by_ancestor(image: str) -> List[str]:
    """
    Busca id real do container associado a imagem

    :param image: Nome da imagem para pesquisa
    :type image: str
    :return: Lista do containers associados as imagens
    :rtype: List[str]
    """
    rc, out, _ = _run(["docker", "ps", "-a", "-q", "--filter", f"ancestor={image}"])
    ids = [x for x in out.splitlines() if x.strip()] if rc == 0 else []

    if not ids and ":" not in image:
        rc, out, _ = _run(["docker", "ps", "-a", "-q", "--filter", f"ancestor={image}:latest"])
        ids = [x for x in out.splitlines() if x.strip()] if rc == 0 else []

    return ids

def _inspect(cont_id: str) -> Optional[dict]:
    """
    Docker container inspect pra extrair dados de exibição

    :param cont_id: ID do container para inspeção
    :type cont_id: str
    :return: Dicionário de parâmetros retornados
    :rtype: Optional[dict]
    """
    rc, out, _ = _run(["docker", "inspect", cont_id])
    if rc != 0 or not out:
        return None
    try:
        data = json.loads(out)
        return data[0] if data else None
    except Exception:
        return None

def _extract_ips(inspected: dict) -> Dict[str, str]:
    """
    Parse no inspect para pegar o IP do container

    :param inspected: Dicionário de parâmetros da inspeção
    :type inspected: dict
    :return: Discionário com o(s) IP(s) do container
    :rtype: Dict[str, str]
    """
    ips: Dict[str, str] = {}
    nets = (inspected.get("NetworkSettings") or {}).get("Networks") or {}
    for net_name, net_data in nets.items():
        ip = (net_data or {}).get("IPAddress") or ""
        if ip:
            ips[net_name] = ip
    return ips

def _pick_preferred_container(container_ids: List[str]) -> Optional[str]:
    """
    Seleção do conteiner exato

    :param container_ids: IDS dos containers para seleção
    :type container_ids: List[str]
    :return: Container ID real
    :rtype: Optional[str]
    """
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

def _get_preferred_container_id_by_ancestor(image_base: str) -> Optional[str]:
    """
    Seleção do conteiner exato pelo nome da imagem

    :param image_base: Nome da imagem
    :type image_base: str
    :return: IDs dos containers retornados
    :rtype: Optional[str]
    """
    ids = _container_ids_by_ancestor(image_base)
    return _pick_preferred_container(ids)

def get_running_container_id_by_ancestor(image_base: str) -> Optional[str]:
    """
    Retorna container_id de um container RUNNING cujo ancestor seja image_base ou image_base:latest.

    :param image_base: Nome da imagem
    :type image_base: str
    :return: IDs dos containers retornados
    :rtype: Optional[str]
    """
    if not docker_available():
        return None

    # 1) tenta com :latest
    rc, out, _ = _run(["docker", "ps", "--filter", f"ancestor={image_base}:latest", "--format", "{{.ID}}"])
    ids = [x.strip() for x in out.splitlines() if x.strip()]
    if rc == 0 and ids:
        return ids[0]

    # 2) tenta sem :latest
    rc, out, _ = _run(["docker", "ps", "--filter", f"ancestor={image_base}", "--format", "{{.ID}}"])
    ids = [x.strip() for x in out.splitlines() if x.strip()]
    if rc == 0 and ids:
        return ids[0]

    return None


def get_container_ip_by_id(cid: str) -> Optional[str]:
    """
    IP do container (bridge). Se tiver múltiplas networks, pega o primeiro IP encontrado.

    :param cid: ID do container
    :type cid: str
    :return: Entereço IP como string
    :rtype: Optional[str]
    """
    if not cid:
        return None
    rc, out, err = _run([
        "docker", "inspect",
        "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}",
        cid
    ])
    if rc != 0:
        return None
    ips = [x for x in out.strip().split() if x]
    return ips[0] if ips else None


def get_required_server_ips() -> Tuple[Optional[List[str]], List[str]]:
    """
    Retorna (ips_em_ordem, missing_labels).
    missing_labels contém os "WEB/SSH/..." que não estão rodando ou sem IP.

    :return: Retorna IPs dos servidores
    :rtype: Tuple[Optional[List[str]], List[str]]
    """
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

# -----------------------------
# Logs dos servidores (view)
# -----------------------------
def fetch_server_logs(image_base: str, tail_lines: int = 200, prefer_alt: bool = False) -> Dict[str, Any]:
    """
    Consulta de logs de um servidor

    :param image_base: Nome da Imagem
    :type image_base: str
    :param tail_lines: Número de linhas de logs para retornas, padrão é 200
    :type tail_lines: int, optional
    :param prefer_alt: Método alternativo, para casos de logs binários, padrão é False
    :type prefer_alt: bool, optional
    :return: Saída padrão do retorno dos logs para exibição
    :rtype: Dict[str, Any]
    """
    if not docker_available():
        return {"ok": False, "mode": "error", "cmd_display": "", "stdout": "", "stderr": "Docker indisponível.", "returncode": 1}

    cid = _get_preferred_container_id_by_ancestor(image_base)
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


def _clip_text(s: str, max_chars: int = 120_000) -> str:
    """
    Definição de retorno máximo de saída textual

    :param s: Valores do tipo string retornados
    :type s: str
    :param max_chars: Máximo de caracteres para um retorno único, padrão é 120.000 caracteres
    :type max_chars: int, optional
    :return: Retorno textual truncado em 120.000 caracteres, caso necessário
    :rtype: str
    """
    if not s:
        return s
    if len(s) <= max_chars:
        return s
    return s[:max_chars] + "\n\n[saída truncada: excedeu o limite de caracteres]"

def render_server_logs_view() -> None:
    """
    Funções streamlit para montar o módulo de visualização de logs
    """
    label = st.session_state.get("server_logs_label", "")
    image_base = st.session_state.get("server_logs_image_base", "")
    st.subheader(f"Logs do servidor: {label}")

    if "server_logs_tail" not in st.session_state:
        st.session_state["server_logs_tail"] = 200

    spec = SERVER_LOG_SPECS.get(image_base, {})
    has_alt = bool(spec.get("alt_sh"))
    is_binary = bool(spec.get("binary"))

    top = st.columns([1, 1, 2])
    if top[0].button("Voltar"):
        st.session_state["view"] = "main"
        st.rerun()

    tail_lines = top[2].number_input("Tail (linhas)", min_value=1, max_value=5000, value=int(st.session_state["server_logs_tail"]), step=50)
    st.session_state["server_logs_tail"] = int(tail_lines)

    if top[1].button("Atualizar logs"):
        st.rerun()

    prefer_alt = False
    if is_binary:
        st.warning(spec.get("binary_hint", "Este log pode ser binário e a saída pode ficar ilegível."))
        if has_alt:
            mode_choice = st.radio("Modo de leitura", options=["Tail raw", spec.get("alt_label", "Alternativo")], horizontal=True, index=0, key="server_logs_mode_choice")
            prefer_alt = (mode_choice != "Tail raw")
            if not prefer_alt:
                st.error("Não é possível exibir este log no modo Tail raw (arquivo binário). Use o modo alternativo.")
                return

    result = fetch_server_logs(image_base, tail_lines=int(tail_lines), prefer_alt=prefer_alt)

    st.caption("Comando executado:")
    st.code(result.get("cmd_display", ""), language="bash")

    out = _clip_text(result.get("stdout", ""))
    err = _clip_text(result.get("stderr", ""))

    if out:
        st.code(out, language="text")
    else:
        st.write("Sem saída de logs.")

    if err:
        with st.expander("stderr", expanded=False):
            st.code(err, language="text")

# -----------------------------
# Capturas + Features (views)
# -----------------------------
def list_capture_files() -> List[Path]:
    """
    Lista de arquivos .pcap no diretório /captures

    :return: Lista de arquivo em formato path em ordem ascendente
    :rtype: List[Path]
    """
    _ensure_dirs()
    return sorted(CAPTURES_DIR.glob("*.pcap"), key=lambda p: p.stat().st_mtime, reverse=True)

def format_bytes(n: int) -> str:
    """
    Função auxiliar para exibir na tela o tamanho do arquivo de captura 

    :param n: Retorno em bytes
    :type n: int
    :return: Conversão adequada human-readable
    :rtype: str
    """
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"

def render_captures_view() -> None:
    """
    Funções streamlit para montar o módulo de visualização das capturas
    """
    st.subheader("Capturas Realizadas")
    top = st.columns([1, 1, 3])
    if top[0].button("Voltar"):
        st.session_state["view"] = "main"
        st.rerun()
    if top[1].button("Atualizar lista"):
        st.rerun()

    files = list_capture_files()
    if not files:
        st.info('Nenhuma captura encontrada em "captures/".')
        return

    query = st.text_input("Filtrar por nome (opcional)", value="").strip().lower()
    if query:
        files = [p for p in files if query in p.name.lower()]

    st.caption(f'Total: {len(files)} arquivo(s) em "{CAPTURES_DIR}/"')

    # Organização em colunas para exibis os botões em uma mesma linha
    h1, h2, h3, h4, h5, h6, h7, h8 = st.columns([4, 1.5, 2, 1.4, 1.6, 1.6, 1.8, 1.8], gap="small")
    h1.write("Arquivo")
    h2.write("Tamanho")
    h3.write("Modificado em")
    h4.write("Download")
    h5.write("Extrair")
    h6.write("Ver features")
    h7.write("Gerar dataset")
    h8.write("Ver dataset")

    for p in files:
        stat = p.stat()
        size = format_bytes(stat.st_size)
        mtime = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")

        # Features existentes?
        outs = build_feature_paths(p)
        existing = {tool: path for tool, path in outs.items() if path.exists()}
        has_features = len(existing) > 0

        # Dataset existente?
        dataset_path = build_dataset_path_for_capture(p)
        has_dataset = dataset_path.exists()

        c1, c2, c3, c4, c5, c6, c7, c8 = st.columns([4, 1.5, 2, 1.4, 1.6, 1.6, 1.8, 1.8], gap="small")
        c1.write(p.name)
        c2.write(size)
        c3.write(mtime)

        # Download PCAP
        with open(p, "rb") as f:
            c4.download_button(
                "Download",
                data=f,
                file_name=p.name,
                mime="application/vnd.tcpdump.pcap",
                key=f"dl_{p.name}",
                use_container_width=True,
            )

        # Extrair features
        if c5.button("Extrair", key=f"fx_{p.name}", type="secondary", use_container_width=True):
            st.session_state["selected_pcap"] = str(p)
            st.session_state["view"] = "features"
            st.rerun()

        # Ver features
        if c6.button("Ver", key=f"vf_{p.name}", type="secondary", use_container_width=True, disabled=not has_features):
            st.session_state["selected_pcap"] = str(p)
            st.session_state["view"] = "view_features"
            st.rerun()

        # Gerar dataset (somente se há features)
        if c7.button("Gerar", key=f"gd_{p.name}", type="secondary", use_container_width=True, disabled=not has_features):
            try:
                from modules.datasets import build_dataset_unsupervised_for_capture
                out_path = build_dataset_unsupervised_for_capture(
                    p,
                    features_dir=FEATURES_DIR,   # ou "features"
                    outdir=DATASETS_DIR,         # ou "datasets"
                )
                st.success(f"Dataset gerado: {Path(out_path).name}")
            except Exception as e:
                st.error("Falha ao gerar dataset.")
                st.code(str(e), language="text")
            st.rerun()

        # Ver dataset (somente se existe)
        if c8.button("Ver", key=f"vd_{p.name}", type="secondary", use_container_width=True, disabled=not has_dataset):
            st.session_state["selected_pcap"] = str(p)
            st.session_state["view"] = "view_dataset"
            st.rerun()

def render_features_view() -> None:
    """
    Funções streamlit para montar o módulo de seleção da visualização de features extraídas
    """
    st.subheader("Extração de Features")
    top = st.columns([1, 3])
    if top[0].button("Voltar"):
        st.session_state["view"] = "captures"
        st.rerun()

    pcap_str = st.session_state.get("selected_pcap", "")
    if not pcap_str:
        st.info("Nenhuma captura selecionada.")
        return

    pcap_path = Path(pcap_str)
    if not pcap_path.exists():
        st.error(f"Arquivo não encontrado: {pcap_path}")
        return

    _ensure_dirs()
    outs = build_feature_paths(pcap_path)

    st.write("Captura selecionada:", str(pcap_path))
    st.markdown("### Saídas previstas")
    st.code("\n".join([str(outs["ntlflowlyzer"]), str(outs["tshark"]), str(outs["scapy"])]), language="text")

    c1, c2, c3 = st.columns(3)
    run_ntl = c1.checkbox("NTLFlowLyzer", value=True)
    run_tsh = c2.checkbox("TShark", value=True)
    run_scp = c3.checkbox("Scapy", value=True)

    overwrite = st.checkbox("Sobrescrever CSVs existentes (se houver)", value=False)

    if st.button("Extrair features", type="primary"):
        results: Dict[str, Any] = {}
        with st.spinner("Executando extração... Esta ação pode levar vários minutos."):
            if run_ntl:
                results["ntlflowlyzer"] = extract_with_ntlflowlyzer(pcap_path, outs["ntlflowlyzer"]) if (overwrite or not outs["ntlflowlyzer"].exists()) else {"ok": True, "output": str(outs["ntlflowlyzer"]), "cmd": ["(skip) já existe"]}
            if run_tsh:
                results["tshark"] = extract_with_tshark(pcap_path, outs["tshark"]) if (overwrite or not outs["tshark"].exists()) else {"ok": True, "output": str(outs["tshark"]), "cmd": ["(skip) já existe"]}
            if run_scp:
                results["scapy"] = extract_with_scapy(pcap_path, outs["scapy"]) if (overwrite or not outs["scapy"].exists()) else {"ok": True, "output": str(outs["scapy"]), "cmd": ["(skip) já existe"]}

        st.markdown("### Resultados")
        for tool, res in results.items():
            if res.get("ok"):
                st.success(f"{tool}: OK → {res.get('output')}")
            else:
                st.error(f"{tool}: falhou")
                if res.get("stderr"):
                    st.code(res["stderr"], language="text")
            if res.get("cmd"):
                st.caption("Comando:")
                st.code(" ".join(res["cmd"]), language="bash")

        if st.button("Ir para Ver features", type="secondary"):
            st.session_state["view"] = "view_features"
            st.rerun()

def _preview_csv(path: Path, n_rows: int) -> Any:
    """
    Funções de manipulação de dados para exibir os resultados no Streamlit

    :param path: Caminho do arquivo csv para exibição
    :type path: Path
    :param n_rows: Número padrão de linhas para exibir
    :type n_rows: int
    :return: Retorna os dados formatados
    :rtype: Any
    """
    try:
        import pandas as pd  # type: ignore
        df = pd.read_csv(path)
        return df.head(n_rows)
    except Exception:
        rows: List[Dict[str, Any]] = []
        with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                if i >= n_rows:
                    break
                rows.append(row)
        return rows

def render_view_dataset_view() -> None:
    """
    Funções streamlit para montar o módulo de visualização dos datasets
    """
    st.subheader("Dataset (não-supervisionado)")

    top = st.columns([1, 1, 3])
    if top[0].button("Voltar"):
        st.session_state["view"] = "captures"
        st.rerun()
    if top[1].button("Atualizar"):
        st.rerun()

    pcap_str = st.session_state.get("selected_pcap", "")
    if not pcap_str:
        st.info("Nenhuma captura selecionada.")
        return

    pcap_path = Path(pcap_str)
    ds_path = build_dataset_path_for_capture(pcap_path)

    st.write("Captura:", str(pcap_path))
    st.write("Dataset:", str(ds_path))

    if not ds_path.exists():
        st.warning("Dataset não encontrado para esta captura.")
        return

    # Download
    with open(ds_path, "rb") as f:
        st.download_button(
            label="Download dataset (CSV)",
            data=f,
            file_name=ds_path.name,
            mime="text/csv",
            use_container_width=False,
        )

    st.divider()

    # Controles de visualização
    c1, c2, c3 = st.columns([1.3, 1.3, 2.4], gap="small")
    preview_n = c1.number_input("Prévia (linhas)", min_value=10, max_value=20000, value=200, step=50)
    max_cols = c2.number_input("Máx. colunas", min_value=10, max_value=300, value=80, step=10)
    search = c3.text_input("Filtro (contém no texto da linha)", value="").strip().lower()

    # Carrega com pandas (preferível)
    try:
        import pandas as pd

        # Lê só as N primeiras linhas para ficar rápido.
        df = pd.read_csv(ds_path, nrows=int(preview_n), engine="python")

        # Limita colunas (muitas colunas deixam pesado)
        if df.shape[1] > int(max_cols):
            df = df.iloc[:, : int(max_cols)]

        # Filtro simples por substring (concatena valores por linha)
        if search:
            mask = df.astype(str).agg(" ".join, axis=1).str.lower().str.contains(search, na=False)
            df = df[mask]

        st.caption(f"Exibindo {len(df)} linha(s) (até {preview_n}) e {df.shape[1]} coluna(s).")
        st.dataframe(df, use_container_width=True, hide_index=True)

    except Exception as e:
        # Fallback sem pandas
        st.warning("Pandas não disponível ou falhou ao ler o CSV. Usando visualização simples.")
        st.code(str(e), language="text")

        import csv

        rows = []
        with ds_path.open("r", encoding="utf-8", errors="replace", newline="") as fp:
            r = csv.reader(fp)
            for i, row in enumerate(r):
                rows.append(row)
                if i >= int(preview_n):
                    breakf

        if rows:
            # Mostra como dataframe “manual”
            header = rows[0]
            data = rows[1:]
            # aplica filtro se houver
            if search:
                data = [r for r in data if search in " ".join(r).lower()]
            st.caption(f"Exibindo {len(data)} linha(s) (até {preview_n})")
            st.dataframe(data, use_container_width=True)  # sem header no fallback
        else:
            st.write("Arquivo vazio.")

def render_view_features_view() -> None:
    """
    Funções streamlit para montar o módulo de visualização de features extraídas
    """
    st.subheader("Features extraídas")
    top = st.columns([1, 3])
    if top[0].button("Voltar"):
        st.session_state["view"] = "captures"
        st.rerun()

    pcap_str = st.session_state.get("selected_pcap", "")
    if not pcap_str:
        st.info("Nenhuma captura selecionada.")
        return

    pcap_path = Path(pcap_str)
    outs = build_feature_paths(pcap_path)
    existing = {tool: path for tool, path in outs.items() if path.exists()}

    st.write("Captura:", str(pcap_path))

    if not existing:
        st.warning("Nenhum arquivo de features encontrado para esta captura.")
        if st.button("Extrair features agora", type="primary"):
            st.session_state["view"] = "features"
            st.rerun()
        return

    st.markdown("### Arquivos encontrados")
    for tool, path in existing.items():
        cols = st.columns([3, 2, 2], gap="small")
        cols[0].write(path.name)
        cols[1].write(tool)
        with open(path, "rb") as f:
            cols[2].download_button("Download CSV", data=f, file_name=path.name, mime="text/csv", key=f"dl_csv_{tool}_{pcap_path.name}", use_container_width=True)

    st.markdown("### Pré-visualização")
    tool_list = list(existing.keys())
    tabs = st.tabs(tool_list)
    for tab, tool in zip(tabs, tool_list):
        with tab:
            csv_path = existing[tool]
            n = st.number_input("Linhas para prévia", min_value=5, max_value=500, value=50, step=5, key=f"preview_n_{tool}_{pcap_path.name}")
            preview = _preview_csv(csv_path, int(n))
            st.dataframe(preview, use_container_width=True)

# -----------------------------
# Host IP e status de servidores
# -----------------------------
def get_host_ip() -> str:
    """
    Retorna o IP real do host

    :return: Retorna endereço IP como string
    :rtype: str
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "-"

@st.cache_data(ttl=5, show_spinner=False)
def get_servers_status() -> List[dict]:
    """
    Retorna o status dos servidores

    :return: Lista de status dos servidores
    :rtype: List[dict]
    """
    rows: List[dict] = [{"Servidor": "Esta máquina", "IP": get_host_ip()}]

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

# -----------------------------
# Captura tcpdump
# -----------------------------
def start_tcpdump_capture(pcap_path: Path, iface: str = "docker0") -> Dict[str, Any]:
    """
    Função para iniciar captura de tráfego

    :param pcap_path: Caminho para o salvar o arquivo .pcap
    :type pcap_path: Path
    :param iface: Interface, fixado na "docker0" para fins da viabilidade do experimento
    :type iface: str, optional
    :return: Dicionário do caminho do arquivo e interface
    :rtype: Dict[str, Any]
    """
    _ensure_dirs()
    cmd = ["tcpdump", "-i", iface, "-w", str(pcap_path)]
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(0.25)
        if p.poll() is not None:
            out = (p.stdout.read() if p.stdout else b"")
            err = (p.stderr.read() if p.stderr else b"")
            return {"ok": False, "cmd": cmd, "popen": None, "stderr": (err or b"").decode("utf-8", errors="replace").strip(), "stdout": (out or b"").decode("utf-8", errors="replace").strip()}
        return {"ok": True, "cmd": cmd, "popen": p, "stdout": "", "stderr": ""}
    except FileNotFoundError:
        return {"ok": False, "cmd": cmd, "popen": None, "stdout": "", "stderr": "tcpdump não encontrado no PATH."}
    except Exception as e:
        return {"ok": False, "cmd": cmd, "popen": None, "stdout": "", "stderr": str(e)}

def stop_tcpdump_capture(p: subprocess.Popen, timeout: float = 3.0) -> Dict[str, Any]:
    """
    Função para interromper a captura

    :param p: ID do subprocesso iniciado
    :type p: subprocess.Popen
    :param timeout: timeout, padrão é 3 segundos
    :type timeout: float, optional
    :return: Dicionário com o ID do subprocesso e timeout
    :rtype: Dict[str, Any]
    """
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
        return {"ok": True, "stdout": (out or b"").decode("utf-8", errors="replace").strip(), "stderr": (err or b"").decode("utf-8", errors="replace").strip()}
    except Exception as e:
        return {"ok": False, "stdout": "", "stderr": str(e)}

# -----------------------------
# Sidebar UI (render)
# -----------------------------
rows = get_servers_status()
ip_map = {r["Servidor"]: r["IP"] for r in rows}

st.sidebar.header("Dados Armazenados")
if st.sidebar.button("Ver Capturas Realizadas", type="secondary"):
    st.session_state["view"] = "captures"
    st.rerun()

st.sidebar.divider()

h1, h2, h3 = st.sidebar.columns([2, 2, 2])
h1.write("**Servidor**")
h2.write("**IP**")
h3.write("**Ver logs**")

c1, c2, c3 = st.sidebar.columns([2, 2, 2])
c1.write("Esta máquina")
c2.write(ip_map.get("Esta máquina", "-"))
c3.write("-")

for label, image_base in SERVER_SPECS:
    c1, c2, c3 = st.sidebar.columns([2, 2, 2], gap="small")
    c1.write(label)
    c2.write(ip_map.get(label, "-"))
    if c3.button("Logs", key=f"logs_btn_{image_base}", type="secondary", use_container_width=True):
        st.session_state["view"] = "server_logs"
        st.session_state["server_logs_label"] = label
        st.session_state["server_logs_image_base"] = image_base
        st.rerun()

if st.sidebar.button("Atualizar"):
    get_servers_status.clear()

st.sidebar.divider()
st.sidebar.header("Clientes benignos")

running_clients = list_running_benign_clients()
x = len(running_clients)

server_ips, missing_servers = get_required_server_ips()
servers_ok = (server_ips is not None)

# desabilita se docker indisponível OU >=10 OU servers não OK
remove_disabled = (x == 0) or (not docker_available())
start_disabled = (x >= CLIENT_MAX_RUNNING) or (not docker_available()) or (not servers_ok)

st.sidebar.write(f"Clientes benignos: **{x}**")
cA, cB = st.sidebar.columns([1, 1], gap="small")
if not servers_ok:
    st.sidebar.warning(
        "Para iniciar clientes benignos, todos os 7 servidores devem estar rodando. "
        f"Faltando: {', '.join(missing_servers)}"
    )

if cA.button("Remover todos os clientes", disabled=remove_disabled, use_container_width=True):
    res = remove_all_benign_clients(running_clients)
    if res.get("ok"):
        st.sidebar.success("Clientes removidos.")
    else:
        st.sidebar.error("Falha ao remover clientes.")
        if res.get("stderr"):
            st.sidebar.caption(res["stderr"])
    st.rerun()

if cB.button("Iniciar um cliente", disabled=start_disabled, use_container_width=True):
    res = start_one_benign_client(running_clients)
    if res.get("ok"):
        st.sidebar.success(f"Iniciado: {res.get('container_name')}")
    else:
        st.sidebar.error("Falha ao iniciar cliente.")
        if res.get("stderr"):
            st.sidebar.caption(res["stderr"])
    st.rerun()

# (Opcional) Mostrar lista compacta dos nomes detectados
with st.sidebar.expander("Detalhes", expanded=False):
    if not running_clients:
        st.write("Nenhum cliente benigno em execução.")
    else:
        st.write(", ".join(name for name, _ in running_clients))


st.sidebar.divider()

# -----------------------------
# Execução / Stop / Status do ataque
# -----------------------------
def run_attack_from_spec(spec: AttackSpec, resolved_params: Dict[str, Any], capture_enabled: bool = True) -> Dict[str, Any]:
    """
    Função de execução dos ataques (controle de containers)

    :param spec: Difinição dos parâmetros do ataque vindos do registry
    :type spec: AttackSpec
    :param resolved_params: Lista de parâmetros para a execução
    :type resolved_params: Dict[str, Any]
    :param capture_enabled: Booleano para ativar automaticamente ou não a captura junto, padrão é True
    :type capture_enabled: bool, optional
    :return: Dicionário de parâmetros
    :rtype: Dict[str, Any]
    """
    if not docker_available():
        return {"ok": False, "stderr": "Docker indisponível no host do Streamlit.", "cmd": [], "returncode": 1}

    if not capture_enabled:
        with st.spinner("Executando ataque..."):
            result = spec.runner(resolved_params)
        result["capture"] = {"enabled": False}
        return result

    pcap_path = build_capture_path(spec.id)
    cap = start_tcpdump_capture(pcap_path, iface="docker0")
    if not cap.get("ok"):
        return {"ok": False, "stderr": f"Falha ao iniciar captura: {cap.get('stderr') or ''}".strip(), "cmd": cap.get("cmd", []), "returncode": 1, "capture": {"enabled": True, "ok": False, "pcap_path": str(pcap_path), **cap}}

    tcpdump_p = cap["popen"]
    with st.spinner("Executando ataque e capturando tráfego..."):
        attack_result = spec.runner(resolved_params)

    if not attack_result.get("ok"):
        stop_info = stop_tcpdump_capture(tcpdump_p)
        attack_result["capture"] = {"enabled": True, "ok": True, "pcap_path": str(pcap_path), "tcpdump_cmd": cap.get("cmd"), "stop": stop_info}
        return attack_result

    container_id = attack_result.get("container_id")
    wait_err = ""
    if container_id:
        rc, out, err = _run(["docker", "wait", container_id])
        if rc != 0:
            wait_err = err or out or "Falha ao aguardar término do container."
    else:
        wait_err = "container_id não retornado; não foi possível aguardar término."

    stop_info = stop_tcpdump_capture(tcpdump_p)
    attack_result["capture"] = {"enabled": True, "ok": True, "pcap_path": str(pcap_path), "tcpdump_cmd": cap.get("cmd"), "wait_error": wait_err, "stop": stop_info}
    return attack_result

def show_last_attack_result(spec: AttackSpec) -> None:
    """
    Estado da sessão de execução

    :param spec: Retorno do estado da última execução da especificação
    :type spec: AttackSpec
    """
    res = st.session_state["last_attack_result"].get(spec.id)
    if not res:
        return

    st.markdown("### Última execução")

    cap = res.get("capture") or {}
    if cap.get("enabled") is False:
        st.write("Captura:", "desativada")

    pcap = cap.get("pcap_path")
    if pcap:
        st.write("Captura:", pcap)
        if cap.get("tcpdump_cmd"):
            st.caption("Comando tcpdump:")
            st.code(" ".join(cap["tcpdump_cmd"]), language="bash")
        if cap.get("wait_error"):
            st.warning(f"Observação: {cap['wait_error']}")

    if res.get("ok"):
        st.success("Ataque iniciado com sucesso.")
        st.write("Container ID:", res.get("container_id") or "-")
    else:
        st.error("Falha ao iniciar o ataque.")
        st.write("Return code:", res.get("returncode"))
        if res.get("stderr"):
            st.code(res["stderr"], language="text")

    st.caption("Comando executado:")
    st.code(" ".join(res.get("cmd", [])), language="bash")

    if st.button("Limpar última saída", key=f"clear_last_{spec.id}"):
        st.session_state["last_attack_result"].pop(spec.id, None)
        st.rerun()

def stop_attack(spec: AttackSpec) -> None:
    """
    Controle manual de parada do ataque

    :param spec: Retorno da especificação para parar o ataque
    :type spec: AttackSpec
    """
    if not spec.container_name:
        st.warning("Este ataque não possui container_name definido; não é possível parar automaticamente.")
        return
    if not docker_available():
        st.error("Docker indisponível no host do Streamlit.")
        return
    result = docker_rm_force(spec.container_name)
    if result.get("ok"):
        st.success("Container do ataque removido.")
    else:
        st.error("Falha ao remover o container do ataque.")
        if result.get("stderr"):
            st.code(result["stderr"], language="text")

def show_attack_runtime(spec: AttackSpec) -> None:
    """
    Exibição do ataque em curso

    :param spec: Retorno da especificação do ataque
    :type spec: AttackSpec
    """
    if not spec.container_name:
        st.info("Este ataque não possui container_name definido; status/stop não disponíveis.")
        return
    status = docker_container_status(spec.container_name)
    if not status.get("exists"):
        st.write("Status do ataque:", "**parado**.")
        return
    st.write("Status do ataque:", status.get("status", "unknown"))
    st.write("Container:", status.get("id") or "-")
    with st.expander("Ver logs (tail 200)", expanded=False):
        logs = docker_logs(spec.container_name, tail=200)
        if logs.get("ok") and logs.get("stdout"):
            st.code(logs["stdout"], language="text")
        elif logs.get("stderr"):
            st.code(logs["stderr"], language="text")
        else:
            st.write("Sem logs disponíveis.")

# -----------------------------
# Formulário dinâmico por schema
# -----------------------------
def validate_ip(value: str) -> bool:
    """
    Função para validação de IP

    :param value: Endereço em string
    :type value: str
    :return: Se é ou não um IP válido
    :rtype: bool
    """
    try:
        ipaddress.ip_address(value.strip())
        return True
    except Exception:
        return False

def validate_port(value: int) -> bool:
    """
    Validação de porta

    :param value: Porta em inteiro
    :type value: int
    :return: Se é ou não uma porta válida
    :rtype: bool
    """
    return 1 <= int(value) <= 65535

def validate_cidr(value: str) -> bool:
    """
    Validação de rede

    :param value: Rede em string
    :type value: str
    :return: Se é ou não uma rede válida
    :rtype: bool
    """
    try:
        ipaddress.ip_network(value.strip(), strict=False)
        return True
    except Exception:
        return False

def resolve_placeholder(p: ParamSpec, host_ip: str) -> str:
    """
    Definição de placeholders (sugestões de preenchimento) com base nas especificações do registry

    :param p: Tipo de parâmetro
    :type p: ParamSpec
    :param host_ip: IP sugerido
    :type host_ip: str
    :return: Placeholder do IP sugerido
    :rtype: str
    """
    ph = getattr(p, "placeholder", None)
    if not ph:
        return ""
    return host_ip if ph == "__HOST_IP__" else str(ph)

def render_params_form(spec: AttackSpec, host_ip: str) -> Tuple[bool, Dict[str, Any], bool]:
    """
    Rederização do formulários de parâmetros de um ataque selecionado

    :param spec: Tipo de parâmetro
    :type spec: AttackSpec
    :param host_ip: IP sugerido
    :type host_ip: str
    :return: Para cada tipo de ataque, um tipo de sugestão de parâmetros para preenchimento
    :rtype: Tuple[bool, Dict[str, Any], bool]
    """
    resolved: Dict[str, Any] = {}
    if not spec.params:
        if spec.no_params_note:
            st.info(spec.no_params_note)
        c1, c2 = st.columns([3, 2])
        capture_enabled = c2.toggle("Iniciar captura de pacotes junto do ataque", value=True, key=f"cap_toggle_{spec.id}")
        submitted = c1.button("Iniciar ataque", key=f"start_noparams_{spec.id}")
        return submitted, resolved, capture_enabled

    with st.form(f"form_{spec.id}", clear_on_submit=False):
        for p in spec.params:
            ph = resolve_placeholder(p, host_ip)
            if p.kind == "port":
                default_port = int(p.default) if p.default is not None else (int(ph) if ph.isdigit() else 1)
                value = st.number_input(p.label, min_value=1, max_value=65535, value=default_port, step=1, key=f"{spec.id}_{p.key}")
                resolved[p.key] = int(value)
            else:
                value = st.text_input(p.label, placeholder=ph if ph else None, value="" if p.default is None else str(p.default), key=f"{spec.id}_{p.key}").strip()
                if not value and ph:
                    value = ph
                    st.caption(f'Campo "{p.label}" vazio; usando valor sugerido: {ph}')
                resolved[p.key] = value

        c1, c2 = st.columns([3, 2])
        submitted = c1.form_submit_button("Iniciar ataque")
        capture_enabled = c2.toggle("Iniciar captura de pacotes junto do ataque", value=True, key=f"cap_toggle_{spec.id}")

    return submitted, resolved, capture_enabled

def validate_params(spec: AttackSpec, params: Dict[str, Any]) -> List[str]:
    """
    Validação dos parâmetros inseridos

    :param spec: Tipo de parâmetro
    :type spec: AttackSpec
    :param params: Dicionário de "valores possíveis"
    :type params: Dict[str, Any]
    :return: Lista validada
    :rtype: List[str]
    """
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

# -----------------------------
# UI em abas por categoria
# -----------------------------
def category_tab_ui(category_name: str, attacks: List[AttackSpec]) -> None:
    """
    Renderizador das tabs das categorias de ataques

    :param category_name: Caterogias especificadas no registry
    :type category_name: str
    :param attacks: Parâmetros específicos do ataque selecionado numa aba
    :type attacks: List[AttackSpec]
    """
    st.subheader(category_name)

    attack_name_to_spec = {a.name: a for a in attacks}
    attack_name = st.selectbox("Ataque", list(attack_name_to_spec.keys()), key=f"attack_select_{category_name}")
    spec = attack_name_to_spec[attack_name]

    left, right = st.columns([2, 3], gap="large")
    host_ip = get_host_ip()

    with left:
        st.markdown("### Detalhes do ataque")
        st.markdown(f"ID: `{spec.id}`")
        st.markdown(f"Nome: {spec.name}")
        st.markdown(f"Descrição: {spec.description}")
        render_tools_links(getattr(spec, "tools", None))
        with st.expander("Detalhes do container", expanded=False):
            st.markdown(f"Image: `{spec.image}`")
            st.markdown(f"Nome: `{spec.container_name}`")
        render_mitre_links(getattr(spec, "mitre", None))
        if getattr(spec, "details_warning", None):
            st.warning(spec.details_warning)
        st.markdown("### Execução")
        show_attack_runtime(spec)

        col1, col2 = st.columns([1, 1])
        if col1.button("Atualizar status", key=f"refresh_status_{spec.id}"):
            st.rerun()
        if col2.button("Parar ataque", key=f"stop_{spec.id}"):
            stop_attack(spec)
            st.rerun()

    with right:
        st.markdown("### Parâmetros")
        submitted, resolved, capture_enabled = render_params_form(spec, host_ip)
        show_last_attack_result(spec)

        if submitted:
            errors = validate_params(spec, resolved)
            if errors:
                for e in errors:
                    st.error(e)
            else:
                result = run_attack_from_spec(spec, resolved, capture_enabled=capture_enabled)
                st.session_state["last_attack_result"][spec.id] = result
                st.rerun()

# -----------------------------
# Router de telas
# -----------------------------
if st.session_state["view"] == "server_logs":
    render_server_logs_view()
    st.stop()
if st.session_state["view"] == "captures":
    render_captures_view()
    st.stop()
if st.session_state["view"] == "features":
    render_features_view()
    st.stop()
if st.session_state["view"] == "view_features":
    render_view_features_view()
    st.stop()
if st.session_state["view"] == "view_dataset":
    render_view_dataset_view()
    st.stop()

# -----------------------------
# Tela principal: abas
# -----------------------------
category_names = list(CATEGORIES.keys())
tabs = st.tabs(category_names)
for tab, category_name in zip(tabs, category_names):
    with tab:
        category_tab_ui(category_name, CATEGORIES[category_name])

st.divider()
st.caption("Simpósio Brasileiro de Redes de Computadores e Sistemas Distribuídos (SBRC) 2026 - Salão de Ferramentas.")
st.caption(
    "Esta ferramenta tem propósito educacional e não deve ser utilizada para atacar endereços externos ao experimento. "
    "Para demonstração, utilize o próprio IP desta máquina como alvo dos ataques (nos ataques diretos a um endereço IP). "
    "Nos ataques em nível de rede, utilize a rede docker (172.17.0.0/16) ou sua rede local."
)