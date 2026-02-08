import json
import subprocess
from typing import Any, Dict, List, Optional, Tuple

def _run(cmd: List[str]) -> Tuple[int, str, str]:
    """
    Comando para execução

    :param cmd: Comando pretendido
    :type cmd: List[str]
    :return: Comando completo com parâmetros
    :rtype: Tuple[int, str, str]
    """
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()

def docker_available() -> bool:
    """
    Verifica se o Docker está disponível pra uso

    :return: Retorna true ou false
    :rtype: bool
    """
    rc, _, _ = _run(["docker", "version"])
    return rc == 0

def docker_container_id_by_name(name: str) -> Optional[str]:
    """
    Regex exata: ^name$ para identificar container

    :param name: Nome parcial
    :type name: str
    :return: Nome exato
    :rtype: Optional[str]
    """
    rc, out, _ = _run(["docker", "ps", "-a", "-q", "--filter", f"name=^{name}$"])
    if rc != 0:
        return None
    cid = out.strip()
    return cid or None

def docker_rm_force(name_or_id: str) -> Dict[str, Any]:
    """
    Remoção de container

    :param name_or_id: Nome ou ID de entrada
    :type name_or_id: str
    :return: Nome ou ID que será usado na remoção forçada
    :rtype: Dict[str, Any]
    """
    rc, out, err = _run(["docker", "rm", "-f", name_or_id])
    return {
        "ok": rc == 0,
        "cmd": ["docker", "rm", "-f", name_or_id],
        "stdout": out,
        "stderr": err,
        "returncode": rc,
    }

def docker_inspect(name_or_id: str) -> Optional[dict]:
    """
    Inspeção de container

    :param name_or_id: Nome ou ID de entrada
    :type name_or_id: str
    :return: Nome ou ID que será usado na inspeção
    :rtype: Dict[str, Any]
    """
    rc, out, _ = _run(["docker", "inspect", name_or_id])
    if rc != 0 or not out:
        return None
    try:
        data = json.loads(out)
        return data[0] if data else None
    except Exception:
        return None

def docker_container_status(name: str) -> Dict[str, Any]:
    """
    Status de container

    :param name_or_id: Nome ou ID de entrada
    :type name_or_id: str
    :return: Nome ou ID que será usado na verificação
    :rtype: Dict[str, Any]
    """
    cid = docker_container_id_by_name(name)
    if not cid:
        return {"exists": False, "name": name, "id": None, "status": "not_found"}

    inspected = docker_inspect(cid)
    if not inspected:
        return {"exists": True, "name": name, "id": cid[:12], "status": "unknown"}

    state = inspected.get("State") or {}
    status = (state.get("Status") or "unknown").lower()
    return {"exists": True, "name": name, "id": cid[:12], "status": status}

def docker_logs(name_or_id: str, tail: int = 200) -> Dict[str, Any]:
    rc, out, err = _run(["docker", "logs", "--tail", str(tail), name_or_id])
    return {
        "ok": rc == 0,
        "cmd": ["docker", "logs", "--tail", str(tail), name_or_id],
        "stdout": out,
        "stderr": err,
        "returncode": rc,
    }

def docker_run_detached(
    *,
    image: str,
    name: str,
    args: List[str],
    remove_if_exists: bool = True,
) -> Dict[str, Any]:
    """
    Execução de container

    :param image: Nome da imagem
    :type image: str
    :param name: Nome do container
    :type name: str
    :param args: Parâmetros associados
    :type args: List[str]
    :param remove_if_exists: Parâmetro de remover se existir, padrão é true
    :type remove_if_exists: bool, optional
    :return: Dicionário com todas as informações da execução
    :rtype: Dict[str, Any]
    """

    if remove_if_exists:
        existing = docker_container_id_by_name(name)
        if existing:
            docker_rm_force(existing)

    cmd = ["docker", "run", "--rm", "-d", "--name", name, image, *args]
    rc, out, err = _run(cmd)
    ok = (rc == 0)

    return {
        "ok": ok,
        "cmd": cmd,
        "container_id": out.strip() if ok else None,
        "stdout": out,
        "stderr": err,
        "returncode": rc,
    }
