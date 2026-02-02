# Ataque "ICMP Tunnel - TCP over ICMP"

> Estabelece um túnel TCP de porta 2222 (SSH) sobre ICMP com o servidor de SSH `172.17.0.x` e executa 100 prompts de login com usuários aleatórios.

### Execução do ataque:
```
docker run --rm -d --name sbrc26-ataque-icmp-tunnel sbrc26-ataque-icmp-tunnel:latest "172.17.0.x"
```
#### Depende de: **`Servidor SSH`**

#### IP do servidor `ssh`:
```
docker container inspect $( docker ps -a | grep 'sbrc26-ataque-ssh-server:latest' | awk '{print $NF}' ) | grep 'IPAddress' | tail -n1 | awk -F'"' '{print $4}'
```
