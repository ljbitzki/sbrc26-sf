# SBRC 2026 - /docker

## Diretório de contêineres Docker para a simulação de ataques

<details><summary>

### Catálogo de ataques e servidores alvo:
</summary>

**Atacantes:**
- **`sbrc26-ataque-arp-scan`**:
  - Executa enumeração de hosts através de ARP request "who-has" para a rede `192.168.0.x/yy`.
- **`sbrc26-ataque-arp-spoof`**:
  - Executa ARP Spoof do gateway da rede `192.168.0.0/16` com gratuitous arp a cada 100ms, por 15 segundos.
- **`sbrc26-ataque-cdp-table-flood`**:
  - Executa 2000 pacotes CDP com informação de vizinhos com endereços MAC aleatórios.
- **`sbrc26-ataque-coap-get-flood`**:
  - Executa rajada de 1000 requisições GET contra `mqtt://192.168.0.x/`.
- **`sbrc26-ataque-dhcp-starvation`**:
  - Executa 1000 requisições DHCP REQUEST com endereços MAC aleatórios.
- **`sbrc26-ataque-dns-tunneling`**:
  - Executa 200 tentativas de resolução de nomes de domínios aleatórios com até 50 caracteres.
- **`sbrc26-ataque-dos-http-simple`**:
  - Executa 200 acessos em subdirtórios de `http://192.168.0.x/`.
- **`sbrc26-ataque-dos-http-slowloris`**:
  - Executa ataque de manutenção de 150 sockets contra `http://192.168.0.x/` utilizando implementação SlowLoris.
- **`sbrc26-ataque-fin-flood`**:
  - Executa 10 segundos de pacotes TCP com a flag FIN para `192.168.0.x` para a porta especificada sem intervalo entre cada pacote
- **`sbrc26-ataque-icmp-flood`**:
  - Executa 10 segundos de pings (ICMP) para `192.168.0.x` sem intervalo entre cada ping e com 1200 bytes de payload.
- **`sbrc26-ataque-icmp-tunnel`**:
  - Estabelece um túnel TCP de porta 22 (SSH) sobre ICMP com o servidor de SSH `192.168.0.x` e executa 100 prompts de login com usuários aleatórios.
- **`sbrc26-ataque-idor-path-traversal`**:
  - Executa ataque de tentativa de acesso a arquivos locais via webserver, através de _wordlist_, contra `http://192.168.0.x/.
- **`sbrc26-ataque-idor-url-parameter`**:
  - Executa ataque de enumeração de parâmetros PHP, através de _wordlist_, contra `http://192.168.0.x/.
- **`sbrc26-ataque-ipv6-mld-flood`**:
  - Executa 10 segundos de rajada de pacotes de milhares de ICMPv6 do tipo Multicast Listener Report (131).
- **`sbrc26-ataque-ipv6-ns-flood`**:
  - Executa 10 segundos de rajada de pacotes de milhares de ICMPv6 do tipo Neighbor Solicitation (135).
- **`sbrc26-ataque-ipv6-ra-flood`**:
  - Executa 10 segundos de rajada de pacotes de milhares de ICMPv6 do tipo Router Advertisement (134).
- **`sbrc26-ataque-mqtt-bruteforce`**:
  - Executa ataque de força-bruta por dicionário de senhas contra `mqtt://192.168.0.x/`.
- **`sbrc26-ataque-mqtt-publisher`**:
  - Executa rajada de 1000 publicações contra `mqtt://192.168.0.x/`.
- **`sbrc26-ataque-php-lfi-enumeration`**:
  - Executa exploração de LFI em aplicação PHP, através de _wordlist_, contra `http://192.168.0.x/ na porta informada.
- **`sbrc26-ataque-ping-sweep`**:
  - Executa pings para varrer uma rede local genérica (10.10.0.0/18) com timeout de 30ms para cada ping.
- **`sbrc26-ataque-port-scanner-aggressive`**:
  - Executa diversas modalidades de nmap (TCP, UDP, enumeração de serviços, versão de OS e módulo de scan de vulnerabilidades) contra `192.168.0.x`.
- **`sbrc26-ataque-port-scanner-os`**:
  - Executa o nmap com os parâmetros para descoberta de versão de OS contra `192.168.0.x`.
- **`sbrc26-ataque-port-scanner-tcp`**:
  - Executa o nmap no modo TCP Scan contra `192.168.0.x`.
- **`sbrc26-ataque-port-scanner-udp`**:
  - Executa o nmap no modo UDP Scan contra `192.168.0.x`.
- **`sbrc26-ataque-port-scanner-vulnerabilities`**:
  - Executa o nmap no modo reconhecimento via plugin com módulo de scan de vulnerabilidades contra `192.168.0.x`.
- **`sbrc26-ataque-psh-flood`**:
  - Executa 10 segundos de pacotes TCP com a flag PSH para `192.168.0.x` para a porta especificada sem intervalo entre cada pacote.
- **`sbrc26-ataque-rst-flood`**:
  - Executa 10 segundos de pacotes TCP com a flag RST para `192.168.0.x` para a porta especificada sem intervalo entre cada pacote.
- **`sbrc26-ataque-smb-enumerating`**:
  - Executa enumeração de diretórios e vulnerabilidades de compartilhamentos samba contra `192.168.0.x`.
- **`sbrc26-ataque-snmp-scanner`**:
  - Executa consultas SNMP em todos os hosts de uma rede, utilizando _wordlist_ de comunidades. `192.168.0.0/24` será utilizada se nenhuma rede for passada como parâmetro.
- **`sbrc26-ataque-sql-injection`**:
  - Executa os testes do pacote sqlmap contra `http://192.168.0.x/`.
- **`sbrc26-ataque-ssh-bruteforce`**:
  - Executa 100 tentativas de login ssh com senhas aleatórias em `root@192.168.0.x`.
- **`sbrc26-ataque-stp-conf-flood`**:
  - Executa 2000 pacotes BPDU com informação de reconfiguração de topologia STP com endereços MAC aleatórios.
- **`sbrc26-ataque-stp-tcn-flood`**:
  - Executa 2000 pacotes BPDU com informação de mudança de topologia STP com endereços MAC aleatórios.
- **`sbrc26-ataque-syn-flood`**:
  - Executa rajada de 500 pacotes TCP SYN para `192.168.0.x` na porta 80 sem intervalo entre pacotes.
- **`sbrc26-ataque-telnet-bruteforce`**:
  - Executa 100 tentativas de login via telnet com senhas aleatórias em `root@192.168.0.x`.
- **`sbrc26-ataque-udp-flood`**:
  - Executa rajada de 10 segundos de pacotes UDP para `192.168.0.x` na porta 80 sem intervalo entre cada pacote.
- **`sbrc26-ataque-web-dir-enumeration`**:
  - Executa enumeração de subdiretórios por _wordlist_ contra `http://192.168.0.x/`.
- **`sbrc26-ataque-web-https-heartbleed`**:
  - Executa 200 requisições contra `http://192.168.0.x/` vulnerável ao bug HeartBleed.
- **`sbrc26-ataque-web-post-bruteforce`**:
  - Executa ataque de força bruta de autenticação via método POST, por _wordlist_, contra `http://192.168.0.x/.
- **`sbrc26-ataque-web-simple-scanner`**:
  - Executa scanner de vulnerabilidades conhecidas em webserver contra `http://192.168.0.x/`.
- **`sbrc26-ataque-web-wide-scanner`**:
  - Executa frameworks de enumeração de vulnerabilidades conhecidas em webserver contra `http://192.168.0.x/`.
- **`sbrc26-ataque-xss-scanner`**:
  - Executa uma varredura automatizada e análise de falhas de parâmetros suscetíveis a XSS contra `http://192.168.0.x/`

**Servidores:**
- **`sbrc26-servidor-http-server`**:
  - Servidor `Web` com Damn Vulnerable Web Application (DVWA).
- **`sbrc26-servidor-ssh-server`**:
  - Servidor Alpine com serviço `SSH` openssh.
- **`sbrc26-servidor-mqtt-broker`**:
  - Servidor Alpine com serviço `MQTT Broker` Eclipse Mosquitto.
- **`sbrc26-servidor-coap-server`**:
  - Servidor Alpine com serviço `CoAP Server` com módulo aiocoap em Python.
- **`sbrc26-servidor-smb-server`**:
  - Servidor Alpine com serviço `SMB` Samba.
- **`sbrc26-servidor-telnet-server`**:
  - Servidor Ubuntu com serviço `telnetd`.
- **`sbrc26-servidor-ssl-heartbleed`**:
  - Servidor `nginx` vulnerável a HeartBleed.

</summary>
</details>

<details><summary>

### Build das imagens:
</summary>

#### Estando no diretório `docker/` deste repositório, tornar executável o script `build_images.sh`::

```
chmod +x build_images.sh
```

#### Construir **todas as imagens**, rodando o script `build_images.sh`:

```
./build_images.sh
```

##### *Além de construir todas as imagens, os servidores alvo dos ataques Web, SSH, SMB, Telnet, CoAP, MQTT e SSL HeartBleed já serão iniciados.*

</details>

<details><summary>

### Execução dos ataques individuais:
</summary>

#### Container `sbrc26-ataque-arp-scan`:

```
docker run --rm -d --name sbrc26-ataque-arp-scan sbrc26-ataque-arp-scan:latest "192.168.0.x/yy"
```
> Executa enumeração de hosts através de ARP request "who-has" para a rede `192.168.0.x/yy`.

#### Container `sbrc26-ataque-arp-spoof`:

```
docker run --rm -d --name sbrc26-ataque-arp-spoof sbrc26-ataque-arp-spoof:latest "192.168.0.x" "192.168.0.0/yy"
```
> Executa ARP Spoof do gateway da rede `192.168.0.0/16` com gratuitous arp a cada 100ms, por 15 segundos.

#### Container `sbrc26-ataque-cdp-table-flood`:

```
docker run --rm -d --name sbrc26-ataque-cdp-table-flood sbrc26-ataque-cdp-table-flood:latest
```
> Executa 2000 pacotes CDP com informação de vizinhos com endereços MAC aleatórios.

#### Container `sbrc26-ataque-coap-get-flood`:

```
docker run --rm -d --name sbrc26-ataque-coap-get-flood sbrc26-ataque-coap-get-flood:latest "192.168.0.x"
```
> Executa rajada de 1000 requisições GET contra `mqtt://192.168.0.x/`

#### Container `sbrc26-ataque-dhcp-starvation`:

```
docker run --rm -d --name sbrc26-ataque-dhcp-starvation sbrc26-ataque-dhcp-starvation:latest
```
> Executa 1000 requisições DHCP REQUEST com endereços MAC aleatórios.

#### Container `sbrc26-ataque-dns-tunneling` para ataque simulado do `site/dns-tunneling-detector.zeek`

```
docker run --rm -d --name sbrc26-ataque-dns-tunneling sbrc26-ataque-dns-tunneling:latest
```
> Executa 200 tentativas de resolução de nomes de domínios aleatórios com até 50 caracteres

#### Container `sbrc26-ataque-dos-http-simple` para ataque simulado do `site/ddos-detector.zeek`

```
docker run --rm -d --name sbrc26-ataque-dos-http-simple sbrc26-ataque-dos-http-simple:latest "192.168.0.x" "8080"
```
> Executa rajada de 200 acessos em subdirtórios aleatórios de `http://192.168.0.x/` na porta informada

#### Container `sbrc26-ataque-dos-http-slowloris`:

```
docker run --rm -d --name sbrc26-ataque-dos-http-slowloris sbrc26-ataque-dos-http-slowloris:latest "192.168.0.x" "8080"
```
> Executa ataque de manutenção de 150 sockets contra `http://192.168.0.x/` utilizando implementação SlowLoris na porta informada.

#### Container `sbrc26-ataque-fin-flood`:

```
docker run --rm -d --name sbrc26-ataque-fin-flood sbrc26-ataque-fin-flood:latest "192.168.0.x" "8080"
```
> Executa 10 segundos de pacotes TCP com a flag FIN para `192.168.0.x` na porta informada sem intervalo entre cada pacote.

#### Container `sbrc26-ataque-icmp-flood` para ataque simulado do `site/icmp-tunnel-detector.zeek`

```
docker run --rm -d --name sbrc26-ataque-icmp-flood sbrc26-ataque-icmp-flood:latest "192.168.0.x"
```
> Executa 10 segundos de pings (ICMP) para `192.168.0.x` sem intervalo entre cada ping e com 1200 bytes de payload

#### Container `sbrc26-ataque-icmp-tunnel`:

```
docker run --rm -d --name sbrc26-ataque-icmp-tunnel sbrc26-ataque-icmp-tunnel:latest "192.168.0.x"
```

> Estabelece um túnel TCP de porta 2222 (SSH) sobre ICMP com o servidor de SSH `192.168.0.x` e executa 100 prompts de login com usuários aleatórios.

#### Container `sbrc26-ataque-idor-path-traversal`:

```
docker run --rm -d --name sbrc26-ataque-web-idor-path-traversal sbrc26-ataque-idor-path-traversal:latest "http://192.168.0.x/" "8080"
```
> Executa ataque de tentativa de acesso a arquivos locais via webserver, através de _wordlist_, contra `http://192.168.0.x/ na porta informada

#### Container `sbrc26-ataque-idor-url-parameter`:

```
docker run --rm -d --name sbrc26-ataque-web-idor-url-parameter sbrc26-ataque-idor-url-parameter:latest `http://192.168.0.x/ "8080"
```
> Executa ataque de enumeração de parâmetros PHP, através de _wordlist_, contra `http://192.168.0.x/ na porta informada

#### Container `sbrc26-ataque-ipv6-mld-flood`:

```
docker run --rm -d --name sbrc26-ataque-ipv6-mld-flood sbrc26-ataque-ipv6-mld-flood:latest
```
> Executa 10 segundos de rajada de pacotes de milhares de ICMPv6 do tipo Multicast Listener Report (131)

#### Container `sbrc26-ataque-ipv6-ns-flood`:

```
docker run --rm -d --name sbrc26-ataque-ipv6-ns-flood sbrc26-ataque-ipv6-ns-flood:latest
```
> Executa 10 segundos de rajada de pacotes de milhares de ICMPv6 do tipo Neighbor Solicitation (135)

#### Container `sbrc26-ataque-ipv6-ra-flood`:

```
docker run --rm -d --name sbrc26-ataque-ipv6-ra-flood sbrc26-ataque-ipv6-ra-flood:latest
```
> Executa 10 segundos de rajada de pacotes de milhares de ICMPv6 do tipo Router Advertisement (134)

#### Container `sbrc26-ataque-mqtt-bruteforce`:

```
docker run --rm -d --name sbrc26-ataque-mqtt-bruteforce sbrc26-ataque-mqtt-bruteforce:latest "192.168.0.x"
```
> Executa ataque de força-bruta por dicionário de senhas contra `mqtt://192.168.0.x/`

#### Container `sbrc26-ataque-mqtt-publisher`:

```
docker run --rm -d --name sbrc26-ataque-mqtt-publisher sbrc26-ataque-mqtt-publisher:latest "192.168.0.x"
```
> Executa rajada de 1000 publicações contra `mqtt://192.168.0.x/`


#### Container `sbrc26-ataque-php-lfi-enumeration`:

```
docker run --rm -d --name sbrc26-ataque-php-lfi-enumeration sbrc26-ataque-php-lfi-enumeration:latest "172.17.0.y" "8080"
```
> Executa exploração de LFI em aplicação PHP, através de _wordlist_, contra `http://172.17.0.x/ na porta informada

#### Container `sbrc26-ataque-ping-sweep`:

```
docker run --rm -d --name sbrc26-ataque-ping-sweep sbrc26-ataque-ping-sweep:latest "10.20.30.0/20"
```
> Executa pings para varrer uma rede local genérica (10.10.0.0/18) com timeout de 30ms para cada ping

#### Container `sbrc26-ataque-port-scanner-aggressive`:

```
docker run --rm -d --name sbrc26-ataque-port-scanner-aggressive sbrc26-ataque-port-scanner-aggressive:latest "192.168.0.x"
```
> Executa diversas modalidades de nmap (TCP, UDP, enumeração de serviços, versão de OS e módulo de scan de vulnerabilidades) contra `192.168.0.x`

#### Container `sbrc26-ataque-port-scanner-os`:

```
docker run --rm -d --name sbrc26-ataque-port-scanner-os sbrc26-ataque-port-scanner-os:latest "192.168.0.x"
```
> Executa o nmap com os parâmetros para descoberta de versão de OS contra `192.168.0.x`

#### Container `sbrc26-ataque-port-scanner-tcp`:

```
docker run --rm -d --name sbrc26-ataque-port-scanner-tcp sbrc26-ataque-port-scanner-tcp:latest "192.168.0.x"
```
> Executa o nmap no modo TCP Scan contra `192.168.0.x`

#### Container `sbrc26-ataque-port-scanner-udp`:

```
docker run --rm -d --name sbrc26-ataque-port-scanner-udp sbrc26-ataque-port-scanner-udp:latest "192.168.0.x"
```
> Executa o nmap no modo UDP Scan contra `192.168.0.x`

#### Container `sbrc26-ataque-port-scanner-vulnerabilities`:

```
docker run --rm -d --name sbrc26-ataque-port-scanner-vulnerabilities sbrc26-ataque-port-scanner-vulnerabilities:latest "192.168.0.x"
```
> Executa o nmap no modo reconhecimento via plugin com módulo de scan de vulnerabilidades contra `192.168.0.x`

```
docker run --rm -d --name sbrc26-ataque-psh-flood sbrc26-ataque-psh-flood:latest "192.168.0.x" "8080"
```
> Executa 10 segundos de pacotes TCP com a flag PSH para `192.168.0.x` na porta informada sem intervalo entre cada pacote.

#### Container `sbrc26-ataque-rst-flood`:

```
docker run --rm -d --name sbrc26-ataque-rst-flood sbrc26-ataque-rst-flood:latest "192.168.0.x" "8080"
```
> Executa 10 segundos de pacotes TCP com a flag RST para `192.168.0.x` na porta informada sem intervalo entre cada pacote.

#### Container `sbrc26-ataque-smb-enumerating:latest`:

```
docker run --rm -d --name sbrc26-ataque-smb-enumerating sbrc26-ataque-smb-enumerating:latest "192.168.0.x"
```
> Executa enumeração de diretórios e vulnerabilidades de compartilhamentos samba `http://192.168.0.x/`

#### Container `sbrc26-ataque-snmp-scanner:latest`:

```
docker run --rm -d --name sbrc26-ataque-snmp-scanner sbrc26-ataque-snmp-scanner:latest "192.168.0.x/yy"
```
> Executa consultas SNMP em todos os hosts de uma rede, utilizando _wordlist_ de comunidades. `192.168.0.0/24` será utilizada se nenhuma rede for passada como parâmetro.

#### Container `sbrc26-ataque-sql-injection` para ataque simulado do `site/sql-injection-detector.zeek`

```
docker run --rm -d --name sbrc26-ataque-sql-injection sbrc26-ataque-sql-injection:latest "192.168.0.x" "8080"
```
> Executa os testes do pacote sqlmap contra `http://192.168.0.x/` na porta informada

#### Container `sbrc26-ataque-ssh-bruteforce` para ataque simulado do `site/bruteforce-detector.zeek`:

```
docker run --rm -d --name sbrc26-ataque-ssh-bruteforce sbrc26-ataque-ssh-bruteforce:latest "192.168.0.x" "2222"
```

> Executa 100 tentativas de login ssh com senhas aleatórias em `root@192.168.0.x` na porta informada.

#### Container `sbrc26-ataque-stp-conf-flood`::

```
docker run --rm -d --name sbrc26-ataque-stp-conf-flood sbrc26-ataque-stp-conf-flood:latest
```

> Executa 2000 pacotes BPDU com informação de reconfiguração de topologia STP com endereços MAC aleatórios.

#### Container `sbrc26-ataque-stp-tcn-flood`::

```
docker run --rm -d --name sbrc26-ataque-stp-tcn-flood sbrc26-ataque-stp-tcn-flood:latest
```

> Executa 2000 pacotes BPDU com informação de mudança de topologia STP com endereços MAC aleatórios.

#### Container `sbrc26-ataque-syn-flood`:

```
docker run --rm -d --name sbrc26-ataque-syn-flood sbrc26-ataque-syn-flood:latest "192.168.0.x" "8080"
```
> Executa rajada de 200 pacotes TCP SYN para `192.168.0.x` sem intervalo entre pacotes na porta informada

#### Container `sbrc26-ataque-telnet-bruteforce`::

```
docker run --rm -d --name sbrc26-ataque-telnet-bruteforce sbrc26-ataque-telnet-bruteforce:latest "192.168.0.x" "2323"
```

> Executa 100 tentativas de login via Telnet com senhas aleatórias em `root@192.168.0.x` na porta informada.

#### Container `sbrc26-ataque-udp-flood`:

```
docker run --rm -d --name sbrc26-ataque-udp-flood sbrc26-ataque-udp-flood:latest "192.168.0.x" "8080"
```
> Executa rajada de 10 segundos de pacotes UDP para `192.168.0.x` na porta informada sem intervalo entre cada pacote

#### Container `sbrc26-ataque-web-dir-enumeration`:

```
docker run --rm -d --name sbrc26-ataque-web-dir-enumeration sbrc26-ataque-web-dir-enumeration:latest "192.168.0.x" "8080"
```
> Executa enumeração de subdiretórios por _wordlist_ contra `http://192.168.0.x/`

### Container `sbrc26-ataque-web-https-heartbleed`:

```
docker run --rm -d --name sbrc26-ataque-web-https-heartbleed sbrc26-ataque-web-https-heartbleed:latest `http://192.168.0.x/ "8443"
```
> Executa 200 requisições contra `http://192.168.0.x/` vulnerável ao bug HeartBleed na porta informada

#### Container `sbrc26-ataque-web-post-bruteforce`:

```
docker run --rm -d --name sbrc26-ataque-web-post-bruteforce sbrc26-ataque-web-post-bruteforce:latest `http://192.168.0.x/ "8080"
```
> Executa ataque de força bruta de autenticação via método POST, por _wordlist_, contra `http://192.168.0.x/ na porta informada

#### Container `sbrc26-ataque-web-simple-scanner`:

```
docker run --rm -d --name sbrc26-ataque-web-simple-scanner sbrc26-ataque-web-simple-scanner:latest "192.168.0.x" "8080"
```
> Executa scanner de vulnerabilidades conhecidas em webserver contra `http://192.168.0.x/`

#### Container `sbrc26-ataque-web-wide-scanner`:

```
docker run --rm -d --name sbrc26-ataque-web-wide-scanner sbrc26-ataque-web-wide-scanner:latest "192.168.0.x" "8080"
```
> Executa frameworks de enumeração de vulnerabilidades conhecidas em webserver contra `http://192.168.0.x/` na porta informada

#### Container `sbrc26-ataque-xss-scanner`:

```
docker run --rm -d --name sbrc26-ataque-xss-scanner sbrc26-ataque-xss-scanner:latest "192.168.0.x" "8080"
```
> Executa uma varredura automatizada e análise de falhas de parâmetros suscetíveis a XSS contra `192.168.0.x` na porta informada

</details>

<details><summary>

### Verificar logs dos ataques nos servidores:
</summary>

#### Logs do servidor `http-server`:
```
docker logs $( docker ps -a | grep 'sbrc26-servidor-http-server:latest' | awk '{print $NF}' )
```

#### Logs `ssh-server`:
```
docker exec -it $( docker ps -a | grep 'sbrc26-servidor-ssh-server:latest' | awk '{print $NF}' ) cat /var/log/auth.log
```

#### Logs `smb-server`:
```
docker exec -it $( docker ps -a | grep 'sbrc26-servidor-ssh-server:latest' | awk '{print $NF}' ) cat /var/log/samba/*
```

#### Logs do servidor `mqtt-broker`:
```
docker logs $( docker ps -a | grep 'sbrc26-servidor-mqtt-broker:latest' | awk '{print $NF}' )
```

#### Logs do servidor `coap-server`:
```
docker logs $( docker ps -a | grep 'sbrc26-servidor-coap-server:latest' | awk '{print $NF}' )
```

#### Logs do servidor `telnet-server`:
```
docker exec -it $( docker ps -a | grep 'sbrc26-servidor-telnet-server:latest' | awk '{print $NF}' ) cat /var/log/wtmp
```

#### Logs do servidor `ssl-heartbleed`:
```
docker exec -it $( docker ps -a | grep 'sbrc26-servidor-ssl-heartbleed:latest' | awk '{print $NF}' ) cat /var/log/access.log
```

</details>

<details><summary>

### Verificar IPs dos servidores na rede Docker:
</summary>

#### IP do servidor `web`:
```
docker container inspect $( docker ps -a | grep 'sbrc26-servidor-http-server:latest' | awk '{print $NF}' ) | grep 'IPAddress' | tail -n1 | awk -F'"' '{print $4}'
```

#### IP do servidor `ssh`:
```
docker container inspect $( docker ps -a | grep 'sbrc26-servidor-ssh-server:latest' | awk '{print $NF}' ) | grep 'IPAddress' | tail -n1 | awk -F'"' '{print $4}'
```

#### IP do servidor `mqtt-broker`:
```
docker container inspect $( docker ps -a | grep 'sbrc26-servidor-mqtt-broker:latest' | awk '{print $NF}' ) | grep 'IPAddress' | tail -n1 | awk -F'"' '{print $4}'
```

#### IP do servidor `coap-server`:
```
docker container inspect $( docker ps -a | grep 'sbrc26-servidor-coap-server:latest' | awk '{print $NF}' ) | grep 'IPAddress' | tail -n1 | awk -F'"' '{print $4}'
```

#### IP do servidor `smb-server`:
```
docker container inspect $( docker ps -a | grep 'sbrc26-servidor-smb-server:latest' | awk '{print $NF}' ) | grep 'IPAddress' | tail -n1 | awk -F'"' '{print $4}'
```

#### IP do servidor `telnet-server`:
```
docker container inspect $( docker ps -a | grep 'sbrc26-servidor-telnet-server:latest' | awk '{print $NF}' ) | grep 'IPAddress' | tail -n1 | awk -F'"' '{print $4}'
```

#### IP do servidor `ssl-heartbleed`:
```
docker container inspect $( docker ps -a | grep 'sbrc26-servidor-ssl-heartbleed:latest' | awk '{print $NF}' ) | grep 'IPAddress' | tail -n1 | awk -F'"' '{print $4}'
```

</details>

<details><summary>

### Limpeza do ambiente:
</summary>

*Parar e remover containers e imagens residuais.*

```
while read -r CONT; do docker rm -f ${CONT}; done < <( docker ps -a | grep 'sbrc26-' | awk '{print $1}' )
while read -r IMG; do docker rmi -f ${IMG}; done < <( docker images --format table | grep 'sbrc26-' | awk '{print $3}' )
```

</details>
