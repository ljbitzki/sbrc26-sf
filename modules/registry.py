from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Union
from modules.runners import docker_run_detached

@dataclass(frozen=True)
class ParamSpec:
    key: str
    label: str
    kind: str  # "ip" | "port" | "cidr" | "text"
    placeholder: Optional[str] = None
    default: Optional[Any] = None

@dataclass(frozen=True)
class AttackSpec:
    id: str
    name: str
    description: str
    image: str
    container_name: str
    params: List[ParamSpec] = field(default_factory=list)
    no_params_note: Optional[str] = None
    details_warning: Optional[str] = None
    mitre: Optional[Union[str, List[str]]] = None
    tools: Optional[List[Dict[str, str]]] = None

    def runner(self, resolved_params: Dict[str, Any]) -> Dict[str, Any]:
        args = [str(resolved_params[p.key]) for p in self.params]
        return docker_run_detached(
            image=self.image,
            name=self.container_name,
            args=args,
        )

def A(
    *,
    id: str,
    name: str,
    description: str,
    image_base: str,
    params: Optional[List[ParamSpec]] = None,
    no_params_note: Optional[str] = None,
    details_warning: Optional[str] = None,
    mitre: Optional[Union[str, List[str]]] = None,
    tools: Optional[List[Dict[str, str]]] = None,
) -> AttackSpec:

    return AttackSpec(
        id=id,
        name=name,
        description=description,
        image=f"{image_base}:latest",
        container_name=image_base,
        params=params or [],
        no_params_note=no_params_note,
        details_warning=details_warning,
        mitre=mitre,
        tools=tools,
    )

CATEGORIES: Dict[str, List[AttackSpec]] = {
    "1) Ataques de Aplicação Web": [
        A(
            id="web_idor_path_traversal",
            name="IDOR Path Traversal",
            description="Tentativas de acesso a arquivos locais via webserver, através de wordlist.",
            image_base="sbrc26-ataque-idor-path-traversal",
            params=[
                ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__"),
                ParamSpec("target_port", "Porta do alvo", "port", placeholder="8080", default=8080),
            ],
            mitre=[
                "https://attack.mitre.org/tactics/TA0043/", 
                "https://attack.mitre.org/techniques/T1595/003/", 
                "https://attack.mitre.org/tactics/TA0001/", 
                "https://attack.mitre.org/techniques/T1190/", 
            ],
            tools=[
                {"ffuf": "https://github.com/ffuf/ffuf"},
            ],
        ),

        A(
            id="php_lfi_enumeration",
            name="PHP LFI Enumeration",
            description="Exploração de LFI (Local File Inclusion) em aplicação PHP, através de wordlist.",
            image_base="sbrc26-ataque-php-lfi-enumeration",
            params=[
                ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__"),
                ParamSpec("target_port", "Porta do alvo", "port", placeholder="8080", default=8080),
            ],
            mitre=[
                "https://attack.mitre.org/tactics/TA0001/", 
                "https://attack.mitre.org/techniques/T1190/", 
            ],
            tools=[
                {"ffuf": "https://github.com/ffuf/ffuf"},
            ],
        ),
        A(
            id="web_sql_injection",
            name="SQL Injection",
            description="Testes de exploração de SQL Injection.",
            image_base="sbrc26-ataque-sql-injection",
            params=[
                ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__"),
                ParamSpec("target_port", "Porta do alvo", "port", placeholder="8080", default=8080),
            ],
            mitre=[
                "https://attack.mitre.org/tactics/TA0043/", 
                "https://attack.mitre.org/tactics/TA0001/", 
                "https://attack.mitre.org/techniques/T1190/", 
                "https://attack.mitre.org/techniques/T1595/002/", 
            ],
            tools=[
                {"sqlmap": "https://github.com/sqlmapproject/sqlmap"},
            ],
        ),
        A(
            id="web_dir_enumeration",
            name="Enumeração de diretórios",
            description="Enumeração de subdiretórios e recursos do webserver através de wordlist.",
            image_base="sbrc26-ataque-web-dir-enumeration",
            params=[
                ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__"),
                ParamSpec("target_port", "Porta do alvo", "port", placeholder="8080", default=8080),
            ],
            details_warning=(
                "Este ataque pode gerar muitos dados se for capturado até seu término automático. "
                "Para fins de demonstração, sugere-se parar manualmente o ataque alguns segundos após iniciado."
            ),
            mitre=[
                "https://attack.mitre.org/tactics/TA0043/", 
                "https://attack.mitre.org/techniques/T1595/003/", 
            ],
            tools=[
                {"gobuster": "https://github.com/OJ/gobuster"},
            ],
        ),
        A(
            id="web_https_heartbleed",
            name="HTTPS Heartbleed",
            description="Scanner/exploração Heartbleed sobre servidor HTTPS vulnerável.",
            image_base="sbrc26-ataque-web-https-heartbleed",
            params=[
                ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__"),
                ParamSpec("target_port", "Porta do alvo", "port", placeholder="8443", default=8443),
            ],
            mitre=[
                "https://attack.mitre.org/tactics/TA0043/", 
                "https://attack.mitre.org/tactics/TA0001/", 
                "https://attack.mitre.org/techniques/T1190/", 
                "https://attack.mitre.org/techniques/T1595/002/", 
            ],
            tools=[
                {"ssltest": "https://github.com/sensepost/heartbleed-poc"},
            ],
        ),
        A(
            id="web_post_bruteforce",
            name="Web POST Bruteforce",
            description="Força bruta de autenticação via POST em aplicação web através de wordlist.",
            image_base="sbrc26-ataque-web-post-bruteforce",
            params=[
                ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__"),
                ParamSpec("target_port", "Porta do alvo", "port", placeholder="8080", default=8080),
            ],
            details_warning=(
                "Este ataque pode gerar muitos dados se for capturado até seu término automático. "
                "Para fins de demonstração, sugere-se parar manualmente o ataque alguns segundos após iniciado."
            ),
            mitre=[
                "https://attack.mitre.org/tactics/TA0006/", 
                "https://attack.mitre.org/techniques/T1110/001/", 
                "https://attack.mitre.org/techniques/T1110/", 
            ],
            tools=[
                {"ffuf": "https://github.com/ffuf/ffuf"},
            ],
        ),
        A(
            id="web_simple_scanner",
            name="Web Simple Scanner",
            description="Scanner simplificado de vulnerabilidades web conhecidas.",
            image_base="sbrc26-ataque-web-simple-scanner",
            params=[
                ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__"),
                ParamSpec("target_port", "Porta do alvo", "port", placeholder="8080", default=8080),
            ],
            mitre=[
                "https://attack.mitre.org/tactics/TA0043/", 
                "https://attack.mitre.org/techniques/T1595/002/", 
            ],
            tools=[
                {"Nikto": "https://github.com/sullo/nikto"},
            ],
        ),
        A(
            id="web_wide_scanner",
            name="Web Wide Scanner",
            description="Scanner amplo de vulnerabilidades web conhecidas.",
            image_base="sbrc26-ataque-web-wide-scanner",
            params=[
                ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__"),
                ParamSpec("target_port", "Porta do alvo", "port", placeholder="8080", default=8080),
            ],
            details_warning=(
                "Este ataque pode gerar muitos dados se for capturado até seu término automático. "
                "Para fins de demonstração, sugere-se parar manualmente o ataque alguns segundos após iniciado."
            ),
            mitre=[
                "https://attack.mitre.org/tactics/TA0043/", 
                "https://attack.mitre.org/techniques/T1595/002/", 
            ],
            tools=[
                {"Spiderfoot": "https://github.com/smicallef/spiderfoot"},
            ],
        ),
        A(
            id="web_xss_scanner",
            name="XSS Scanner",
            description="Varredura automatizada e análise de falhas de parâmetros suscetíveis a XSS.",
            image_base="sbrc26-ataque-xss-scanner",
            params=[
                ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__"),
                ParamSpec("target_port", "Porta do alvo", "port", placeholder="8080", default=8080),
            ],
            mitre=[
                "https://attack.mitre.org/tactics/TA0043/", 
                "https://attack.mitre.org/tactics/TA0001/", 
                "https://attack.mitre.org/techniques/T1190/", 
                "https://attack.mitre.org/techniques/T1595/002/", 
            ],
            tools=[
                {"Dalfox": "https://github.com/hahwul/dalfox"},
            ],
        ),
    ],

    "2) Força Bruta": [
        A(
            id="bf_ssh",
            name="SSH Bruteforce",
            description="Força bruta de autenticação SSH.",
            image_base="sbrc26-ataque-ssh-bruteforce",
            params=[
                ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__"),
                ParamSpec("target_port", "Porta do alvo", "port", placeholder="2222", default=2222),
            ],
            mitre=[
                "https://attack.mitre.org/tactics/TA0006/", 
                "https://attack.mitre.org/techniques/T1110/001/", 
            ],
            tools=[
                {"Hydra": "https://github.com/vanhauser-thc/thc-hydra"},
            ],
        ),
        A(
            id="bf_telnet",
            name="Telnet Bruteforce",
            description="Força bruta de autenticação Telnet.",
            image_base="sbrc26-ataque-telnet-bruteforce",
            params=[
                ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__"),
                ParamSpec("target_port", "Porta do alvo", "port", placeholder="2323", default=2323),
            ],
            mitre=[
                "https://attack.mitre.org/tactics/TA0006/", 
                "https://attack.mitre.org/techniques/T1110/001/", 
            ],
            tools=[
                {"Hydra": "https://github.com/vanhauser-thc/thc-hydra"},
            ],
        ),
    ],

    "3) Protocolos IoT": [
        A(
            id="iot_coap_get_flood",
            name="CoAP GET Flood",
            description="Flood de requisições GET em protocolo CoAP.",
            image_base="sbrc26-ataque-coap-get-flood",
            params=[ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__")],
            mitre=[
                "https://attack.mitre.org/tactics/TA0040/", 
                "https://attack.mitre.org/techniques/T1499/", 
                "https://attack.mitre.org/techniques/T1499/003/", 
            ],
            tools=[
                {"aiocoap": "https://aiocoap.readthedocs.io/en/latest/"},
            ],
        ),
        A(
            id="iot_mqtt_bruteforce",
            name="MQTT Bruteforce",
            description="Flood de requisições GET em protocolo MQTT através de wordlist.",
            image_base="sbrc26-ataque-mqtt-bruteforce",
            params=[ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__")],
            mitre=[
                "https://attack.mitre.org/tactics/TA0006/", 
                "https://attack.mitre.org/techniques/T1110/001/", 
                "https://attack.mitre.org/techniques/T1110/", 
            ],
            tools=[
                {"ralmqtt": "https://github.com/Red-Alert-Labs/ralmqtt/"},
            ],
        ),
        A(
            id="iot_mqtt_publisher",
            name="MQTT Publisher",
            description="Flood de publicações em protocolo MQTT.",
            image_base="sbrc26-ataque-mqtt-publisher",
            params=[ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__")],
            mitre=[
                "https://attack.mitre.org/tactics/TA0040/", 
                "https://attack.mitre.org/techniques/T1499/002/", 
            ],
            tools=[
                {"eclipse-mosquitto": "https://github.com/eclipse-mosquitto/mosquitto"},
            ],
        ),
    ],

    "4) DoS e Impacto": [
        A(
            id="dos_http_simple",
            name="DoS HTTP Simple",
            description="DoS simples de aplicação HTTP.",
            image_base="sbrc26-ataque-dos-http-simple",
            params=[
                ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__"),
                ParamSpec("target_port", "Porta do alvo", "port", placeholder="8080", default=8080),
            ],
            mitre=[
                "https://attack.mitre.org/tactics/TA0043/", 
                "https://attack.mitre.org/techniques/T1595/", 
                "https://attack.mitre.org/tactics/TA0040/", 
                "https://attack.mitre.org/techniques/T1499/003/", 
            ],
            tools=[
                {"curl": "https://curl.se/"},
                {"bash" "https://www.gnu.org/software/bash/"},
            ],
        ),
        A(
            id="dos_http_slowloris",
            name="DoS HTTP Slowloris",
            description="DoS do tipo Slowloris de aplicação HTTP.",
            image_base="sbrc26-ataque-dos-http-slowloris",
            params=[
                ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__"),
                ParamSpec("target_port", "Porta do alvo", "port", placeholder="8080", default=8080),
            ],
            mitre=[
                "https://attack.mitre.org/tactics/TA0040/", 
                "https://attack.mitre.org/techniques/T1499/003/", 
            ],
            tools=[
                {"SlowLoris": "https://github.com/gkbrk/slowloris.git"},
            ],
        ),
        A(
            id="dos_fin_flood",
            name="FIN Flood",
            description="Flood de pacotes TCP com a flag FIN.",
            image_base="sbrc26-ataque-fin-flood",
            params=[
                ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__"),
                ParamSpec("target_port", "Porta do alvo", "port", placeholder="8080", default=8080),
            ],
            details_warning=(
                "Este ataque pode gerar muitos dados se for capturado até seu término automático. "
                "Para fins de demonstração, sugere-se parar manualmente o ataque alguns segundos após iniciado."
            ),
            mitre=[
                "https://attack.mitre.org/tactics/TA0007/", 
                "https://attack.mitre.org/techniques/T1595/001/", 
                "https://attack.mitre.org/techniques/T1046/", 
            ],
            tools=[
                {"hping3": "http://www.hping.org/"},
            ],
        ),
        A(
            id="dos_icmp_flood",
            name="ICMP Flood",
            description="Flood de pacotes ICMP.",
            image_base="sbrc26-ataque-icmp-flood",
            params=[ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__")],
            details_warning=(
                "Este ataque pode gerar muitos dados se for capturado até seu término automático. "
                "Para fins de demonstração, sugere-se parar manualmente o ataque alguns segundos após iniciado."
            ),
            mitre=[
                "https://attack.mitre.org/tactics/TA0040/", 
                "https://attack.mitre.org/techniques/T1498/001/", 
            ],
            tools=[
                {"hping3": "http://www.hping.org/"},
            ],
        ),
        A(
            id="dos_psh_flood",
            name="PSH Flood",
            description="Flood de pacotes TCP com a flag PSH.",
            image_base="sbrc26-ataque-psh-flood",
            params=[
                ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__"),
                ParamSpec("target_port", "Porta do alvo", "port", placeholder="8080", default=8080),
            ],
            details_warning=(
                "Este ataque pode gerar muitos dados se for capturado até seu término automático. "
                "Para fins de demonstração, sugere-se parar manualmente o ataque alguns segundos após iniciado."
            ),
            mitre=[
                "https://attack.mitre.org/tactics/TA0040/", 
                "https://attack.mitre.org/techniques/T1498/001/", 
            ],
            tools=[
                {"hping3": "http://www.hping.org/"},
            ],
        ),
        A(
            id="dos_rst_flood",
            name="RST Flood",
            description="Flood de pacotes TCP com a flag RST.",
            image_base="sbrc26-ataque-rst-flood",
            params=[
                ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__"),
                ParamSpec("target_port", "Porta do alvo", "port", placeholder="8080", default=8080),
            ],
            details_warning=(
                "Este ataque pode gerar muitos dados se for capturado até seu término automático. "
                "Para fins de demonstração, sugere-se parar manualmente o ataque alguns segundos após iniciado."
            ),
            mitre=[
                "https://attack.mitre.org/tactics/TA0040/", 
                "https://attack.mitre.org/techniques/T1498/001/", 
            ],
            tools=[
                {"hping3": "http://www.hping.org/"},
            ],
        ),
        A(
            id="dos_syn_flood",
            name="SYN Flood",
            description="Flood de pacotes TCP com a flag SYN.",
            image_base="sbrc26-ataque-syn-flood",
            params=[
                ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__"),
                ParamSpec("target_port", "Porta do alvo", "port", placeholder="8080", default=8080),
            ],
            details_warning=(
                "Este ataque pode gerar muitos dados se for capturado até seu término automático. "
                "Para fins de demonstração, sugere-se parar manualmente o ataque alguns segundos após iniciado."
            ),
            mitre=[
                "https://attack.mitre.org/tactics/TA0040/", 
                "https://attack.mitre.org/techniques/T1498/001/", 
            ],
            tools=[
                {"hping3": "http://www.hping.org/"},
            ],
        ),
        A(
            id="dos_udp_flood",
            name="UDP Flood",
            description="Flood de pacotes UDP.",
            image_base="sbrc26-ataque-udp-flood",
            params=[
                ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__"),
                ParamSpec("target_port", "Porta do alvo", "port", placeholder="8080", default=8080),
            ],
            details_warning=(
                "Este ataque pode gerar muitos dados se for capturado até seu término automático. "
                "Para fins de demonstração, sugere-se parar manualmente o ataque alguns segundos após iniciado."
            ),
            mitre=[
                "https://attack.mitre.org/tactics/TA0040/", 
                "https://attack.mitre.org/techniques/T1498/001/", 
            ],
            tools=[
                {"hping3": "http://www.hping.org/"},
            ],
        ),
    ],

    "5) Reconhecimento / Descoberta": [
        A(
            id="recon_arp_scan",
            name="ARP Scan",
            description="Enumeração de hosts via ARP na rede alvo.",
            image_base="sbrc26-ataque-arp-scan",
            params=[ParamSpec("target_net", "Rede alvo", "cidr", placeholder="192.168.0.0/24")],
            mitre=[
                "https://attack.mitre.org/tactics/TA0007/", 
                "https://attack.mitre.org/techniques/T1018/", 
                "https://attack.mitre.org/techniques/T1595/001/", 
            ],
            tools=[
                {"arp-scan": "https://github.com/royhills/arp-scan"},
            ],
        ),
        A(
            id="recon_ping_sweep",
            name="Ping Sweep",
            description="Varredura ICMP para descoberta de hosts.",
            image_base="sbrc26-ataque-ping-sweep",
            params=[ParamSpec("target_net", "Rede alvo", "cidr", placeholder="192.168.0.0/24")],
            mitre=[
                "https://attack.mitre.org/tactics/TA0007/", 
                "https://attack.mitre.org/techniques/T1018/", 
                "https://attack.mitre.org/techniques/T1595/001/", 
            ],
            tools=[
                {"fping": "https://www.fping.org/"},
            ],
        ),
        A(
            id="recon_port_scanner_aggressive",
            name="Port Scanner Aggressive",
            description="Varredura de portas/serviços com perfil agressivo.",
            image_base="sbrc26-ataque-port-scanner-aggressive",
            params=[ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__")],
            mitre=[
                "https://attack.mitre.org/tactics/TA0007/", 
                "https://attack.mitre.org/techniques/T1595/001/", 
                "https://attack.mitre.org/tactics/TA0043/", 
                "https://attack.mitre.org/techniques/T1046/", 
                "https://attack.mitre.org/techniques/T1595/002/", 
            ],
            tools=[
                {"Nmap": "https://nmap.org/"},
            ],
        ),
        A(
            id="recon_port_scanner_os",
            name="Port Scanner OS",
            description="Detecção de Sistema Operacional (fingerprinting) do alvo.",
            image_base="sbrc26-ataque-port-scanner-os",
            params=[ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__")],
            mitre=[
                "https://attack.mitre.org/tactics/TA0007/", 
                "https://attack.mitre.org/techniques/T1595/001/", 
                "https://attack.mitre.org/tactics/TA0043/", 
                "https://attack.mitre.org/techniques/T1046/", 
            ],
            tools=[
                {"Nmap": "https://nmap.org/"},
            ],
        ),
        A(
            id="recon_port_scanner_tcp",
            name="Port Scanner TCP",
            description="Varredura de portas TCP do alvo.",
            image_base="sbrc26-ataque-port-scanner-tcp",
            params=[ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__")],
            mitre=[
                "https://attack.mitre.org/tactics/TA0007/", 
                "https://attack.mitre.org/techniques/T1595/001/", 
                "https://attack.mitre.org/tactics/TA0043/", 
                "https://attack.mitre.org/techniques/T1046/", 
            ],
            tools=[
                {"Nmap": "https://nmap.org/"},
            ],
        ),
        A(
            id="recon_port_scanner_udp",
            name="Port Scanner UDP",
            description="Varredura de portas UDP do alvo.",
            image_base="sbrc26-ataque-port-scanner-udp",
            params=[ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__")],
            mitre=[
                "https://attack.mitre.org/tactics/TA0007/", 
                "https://attack.mitre.org/techniques/T1595/001/", 
                "https://attack.mitre.org/tactics/TA0043/", 
                "https://attack.mitre.org/techniques/T1046/", 
            ],
            tools=[
                {"Nmap": "https://nmap.org/"},
            ],
        ),
        A(
            id="recon_port_scanner_vuln",
            name="Port Scanner Vulnerabilities",
            description="Varredura de portas e checagem de vulnerabilidades conhecidas.",
            image_base="sbrc26-ataque-port-scanner-vulnerabilities",
            params=[ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__")],
            mitre=[
                "https://attack.mitre.org/tactics/TA0043/", 
                "https://attack.mitre.org/techniques/T1595/002/", 
            ],
            tools=[
                {"Nmap": "https://nmap.org/"},
            ],
        ),
        A(
            id="recon_smb_enum",
            name="SMB Enumerating",
            description="Enumeração de diretórios e vulnerabilidades de compartilhamentos SMB.",
            image_base="sbrc26-ataque-smb-enumerating",
            params=[ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__")],
            mitre=[
                "https://attack.mitre.org/tactics/TA0007/", 
                "https://attack.mitre.org/tactics/TA0043/", 
                "https://attack.mitre.org/techniques/T1595/002/", 
                "https://attack.mitre.org/techniques/T1135/", 
            ],
            tools=[
                {"enum4linux-ng": "https://github.com/cddmp/enum4linux-ng.git"},
            ],
        ),
        A(
            id="recon_snmp_scanner",
            name="SNMP Scanner",
            description="Scanner SNMP em todos os hosts de uma rede, através de wordlist de comunidades.",
            image_base="sbrc26-ataque-snmp-scanner",
            params=[ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__")],
            mitre=[
                "https://attack.mitre.org/tactics/TA0007/", 
                "https://attack.mitre.org/tactics/TA0006/", 
                "https://attack.mitre.org/techniques/T1046/", 
                "https://attack.mitre.org/techniques/T1110/001/", 
            ],
            tools=[
                {"onesixtyone": "https://github.com/trailofbits/onesixtyone"},
            ],
        ),
    ],

    "6) Interceptação / Exploração de Rede": [
        A(
            id="net_arp_spoof",
            name="ARP Spoof",
            description="Ataque de interceptação via ARP Spoofing do Gateway da rede.",
            image_base="sbrc26-ataque-arp-spoof",
            params=[
                ParamSpec("target_net", "Rede alvo", "cidr", placeholder="192.168.0.0/24"),
                ParamSpec("spoof_gw", "Spoofed Gateway", "ip", placeholder="192.168.0.1"),
            ],
            mitre=[
                "https://attack.mitre.org/tactics/TA0006/", 
                "https://attack.mitre.org/techniques/T1557/", 
                "https://attack.mitre.org/techniques/T1557/002/", 
            ],
            tools=[
                {"ArpSpoof": "https://github.com/smikims/arpspoof"},
            ],
        ),
        A(
            id="net_cdp_table_flood",
            name="CDP Table Flood",
            description="Flood de tabela CDP (Cisco Discovery Protocol) em rede local.",
            image_base="sbrc26-ataque-cdp-table-flood",
            params=[],
            no_params_note="Este ataque não recebe parâmetros e atua em nível de rede local.",
            details_warning=(
                "Este ataque pode gerar muitos dados se for capturado até seu término automático. "
                "Para fins de demonstração, sugere-se parar manualmente o ataque alguns segundos após iniciado."
            ),
            mitre=[
                "https://attack.mitre.org/tactics/TA0040/", 
                "https://attack.mitre.org/techniques/T1498/", 
                "https://attack.mitre.org/techniques/T1498/001/", 
            ],
            tools=[
                {"Yersinia": "https://github.com/tomac/yersinia"},
            ],
        ),
        A(
            id="net_dhcp_starvation",
            name="DHCP Starvation",
            description="Exaustão de leases DHCP em rede local.",
            image_base="sbrc26-ataque-dhcp-starvation",
            params=[],
            no_params_note="Este ataque não recebe parâmetros e atua em nível de rede local.",
            mitre=[
                "https://attack.mitre.org/tactics/TA0040/", 
                "https://attack.mitre.org/techniques/T1499/", 
                "https://attack.mitre.org/techniques/T1499/002/",
            ],
            tools=[
                {"Yersinia": "https://github.com/tomac/yersinia"},
            ],
        ),
        A(
            id="net_stp_conf_flood",
            name="STP Config Flood",
            description="Flood de pacotes BPDU (Bridge Protocol Data Units) com informação de reconfiguração de topologia STP com endereços MAC aleatórios.",
            image_base="sbrc26-ataque-stp-conf-flood",
            params=[],
            no_params_note="Este ataque não recebe parâmetros e atua em nível de rede local.",
            details_warning=(
                "Este ataque pode gerar muitos dados se for capturado até seu término automático. "
                "Para fins de demonstração, sugere-se parar manualmente o ataque alguns segundos após iniciado."
            ),
            mitre=[
                "https://attack.mitre.org/tactics/TA0040/", 
                "https://attack.mitre.org/techniques/T1498/001/", 
                "https://attack.mitre.org/techniques/T1565/002/", 
            ],
            tools=[
                {"Yersinia": "https://github.com/tomac/yersinia"},
            ],
        ),
        A(
            id="net_stp_tcn_flood",
            name="STP TCN Flood",
            description="Flood de pacotes BPDU (Bridge Protocol Data Units) com informação de mudança de topologia STP com endereços MAC aleatórios.",
            image_base="sbrc26-ataque-stp-tcn-flood",
            params=[],
            no_params_note="Este ataque não recebe parâmetros e atua em nível de rede local.",
            details_warning=(
                "Este ataque pode gerar muitos dados se for capturado até seu término automático. "
                "Para fins de demonstração, sugere-se parar manualmente o ataque alguns segundos após iniciado."
            ),
            mitre=[
                "https://attack.mitre.org/tactics/TA0040/", 
                "https://attack.mitre.org/techniques/T1498/001/", 
                "https://attack.mitre.org/techniques/T1565/002/", 
            ],
            tools=[
                {"Yersinia": "https://github.com/tomac/yersinia"},
            ],
        ),
        A(
            id="net_ipv6_mld_flood",
            name="IPv6 MLD Flood",
            description="Flood ICMPv6 do tipo Multicast Listener Report MLD (131) em rede local.",
            image_base="sbrc26-ataque-ipv6-mld-flood",
            params=[],
            no_params_note="Este ataque não recebe parâmetros e atua em nível de rede local.",
            details_warning=(
                "Este ataque pode gerar muitos dados se for capturado até seu término automático. "
                "Para fins de demonstração, sugere-se parar manualmente o ataque alguns segundos após iniciado."
            ),
            mitre=[
                "https://attack.mitre.org/tactics/TA0040/", 
                "https://attack.mitre.org/techniques/T1498/001/", 
            ],
            tools=[
                {"thc-ipv6": "https://github.com/vanhauser-thc/thc-ipv6"},
            ],
        ),
        A(
            id="net_ipv6_ns_flood",
            name="IPv6 NS Flood",
            description="Flood ICMPv6 do tipo Neighbor Solicitation NS (135) em rede local.",
            image_base="sbrc26-ataque-ipv6-ns-flood",
            params=[],
            no_params_note="Este ataque não recebe parâmetros e atua em nível de rede local.",
            details_warning=(
                "Este ataque pode gerar muitos dados se for capturado até seu término automático. "
                "Para fins de demonstração, sugere-se parar manualmente o ataque alguns segundos após iniciado."
            ),
            mitre=[
                "https://attack.mitre.org/tactics/TA0007/", 
                "https://attack.mitre.org/techniques/T1018/", 
                "https://attack.mitre.org/techniques/T1595/001/", 
            ],
            tools=[
                {"thc-ipv6": "https://github.com/vanhauser-thc/thc-ipv6"},
            ],
        ),
        A(
            id="net_ipv6_ra_flood",
            name="IPv6 RA Flood",
            description="Flood ICMPv6 do tipo Router Advertisement RA (134) em rede local.",
            image_base="sbrc26-ataque-ipv6-ra-flood",
            params=[],
            no_params_note="Este ataque não recebe parâmetros e atua em nível de rede local.",
            details_warning=(
                "Este ataque pode gerar muitos dados se for capturado até seu término automático. "
                "Para fins de demonstração, sugere-se parar manualmente o ataque alguns segundos após iniciado."
            ),
            mitre=[
                "https://attack.mitre.org/tactics/TA0006/", 
                "https://attack.mitre.org/techniques/T1557/", 
            ],
            tools=[
                {"thc-ipv6": "https://github.com/vanhauser-thc/thc-ipv6"},
            ],
        ),
    ],

    "7) Exfiltração": [
        A(
            id="exf_dns_tunneling",
            name="DNS Tunneling",
            description="Comportamento de Exfiltração via DNS tunneling com resolução de nomes de domínios aleatórios.",
            image_base="sbrc26-ataque-dns-tunneling",
            params=[],
            no_params_note=(
                "Este ataque não recebe parâmetros. Serão utilizados os servidores DNS "
                "1.1.1.1, 1.0.0.1, 8.8.8.8, 8.8.4.4, 9.9.9.9, 149.112.112.112 e 76.76.19.19."
            ),
            mitre=[
                "https://attack.mitre.org/tactics/TA0040/", 
                "https://attack.mitre.org/techniques/T1499/", 
                "https://attack.mitre.org/techniques/T1499/002/",
            ],
            tools=[
                {"bash": "https://www.gnu.org/software/bash/"},
                {"dig": "https://man.archlinux.org/man/dig.1"},
            ],
        ),
        A(
            id="exf_icmp_tunnel",
            name="ICMP Tunnel",
            description="Túnel TCP de porta 22 (SSH) sobre ICMP (pings).",
            image_base="sbrc26-ataque-icmp-tunnel",
            params=[
                ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__"),
                ParamSpec("target_port", "Porta do alvo", "port", placeholder="2222", default=2222),
            ],
            mitre=[
                "https://attack.mitre.org/tactics/TA0006/", 
                "https://attack.mitre.org/tactics/TA0011/", 
                "https://attack.mitre.org/techniques/T1572/", 
                "https://attack.mitre.org/techniques/T1095/", 
                "https://attack.mitre.org/techniques/T1110/001/", 
            ],
            tools=[
                {"openssh-client": "https://www.openssh.org/"},
                {"ptunnel-ng": "https://github.com/utoni/ptunnel-ng"},
            ],
        ),
    ],
}
