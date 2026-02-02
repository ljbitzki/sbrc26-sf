# Servidor "Telnet"

> Servidor Ubuntu com serviço `telnetd` aceitando conexões padrão telnet.

#### IP do servidor `Telnet`:
```
docker container inspect $( docker ps -a | grep 'sbrc26-servidor-telnet-server:latest' | awk '{print $NF}' ) | grep 'IPAddress' | tail -n1 | awk -F'"' '{print $4}'
```
