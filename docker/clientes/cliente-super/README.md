## Cliente multi protocolo.

- `WEB (HTTP/HTTPS)`: curl faz um GET em / (HTTPS se porta=443, senão HTTP). Padrões: 80/443.
- `SMB`: smbclient -L //IP lista shares (tentando credenciais aleatórias). Padrão: 445.
- `SSH`: paramiko tenta abrir sessão SSH com credenciais aleatórias (timeout 1s). Padrão: 22.
- `RDP`: xfreerdp tenta autenticação (+auth-only) com credenciais aleatórias (protegido com timeout 1s). Padrão: 3389.
- `TELNET`: conexão TCP e envio de usuário/senha aleatórios (bem simples). Padrão: 23.
- `SMTP`: conexão TCP, EHLO, tentativa AUTH LOGIN com credenciais aleatórias, QUIT. Padrão: 25.
- `IMAP`: conexão TCP, LOGIN user pass, LOGOUT. Padrão: 143.
- `POP3`: conexão TCP, USER/PASS, QUIT. Padrão: 110.
- `FTP`: conexão TCP, USER/PASS, QUIT. Padrão: 21.
- `DNS`: dig @IP -p PORT example.com A com +time=1 +tries=1. Padrão: 53.
- `SNMP`: snmpget v2c em sysUpTime.0 com community aleatória, -t 1 -r 0. Padrão: 161.
- `SIP`: envia um OPTIONS via UDP (mensagem SIP mínima) e aguarda resposta até 1s. Padrões: 5060 (sem TLS) e 5061 (TLS).
- `CoAP`: coap-client -m get coap://IP:PORT/.well-known/core. Padrão: 5683.
- `MQTT`: mosquitto_pub publica em um tópico aleatório com user/pass aleatórios. Padrão: 1883.
- `Zenoh-Pico (Zenoh)`: tentativa leve de conectividade (TCP connect; fallback UDP probe). Em Zenoh, o protocolo via TCP usa 7447; e há scouting multicast em UDP (ex.: 7446 em modo peer).
- `XRCE-DDS` (Micro XRCE-DDS): envio de datagrama UDP “probe” (benigno) ao agente. Um valor comum de porta do agente é 8888/UDP (muito usado em integrações como PX4).


### Parâmetros:

`SERVIÇO` `IP` `PORTA` `MÁXIMO DE ACESSOS` `INTERVALO ENTRE ACESSOS` `MÁXIMO TOTAL EXECUÇÃO`

**Exemplo 1**:
Executar por até 15s, até 10 requisições de serviço WEB em https://172.17.0.2:443/, com intervalo de 1s entre requisições.
```
docker run --rm --name sbrc26-clientes-super sbrc26-clientes-super:latest web 172.17.0.2 443 10 1 15
```

**Exemplo 2**:
Executar por até 30s, até 25 requisições de serviço FTP em ftp://172.17.0.7:21/, com intervalo de 2s entre requisições, usando usuário e senha aleatórias.
```
docker run --rm --name sbrc26-clientes-super sbrc26-clientes-super:latest ftp 172.17.0.7 21 25 2 30
```