# Ataque "Ping Flood"

> Executa 10 segundos de pings (ICMP) para `172.17.0.x` sem intervalo entre cada ping e com 1200 bytes de payload

### Execução do ataque:
```
docker run --rm -d --name sbrc26-ataque-icmp-flood sbrc26-ataque-icmp-flood:latest "172.17.0.x"
```
#### Depende de: **`Servidor Web`**

#### IP do servidor `http-server`:
```
docker container inspect $( docker ps -a | grep 'sbrc26-ataque-http-server:latest' | awk '{print $NF}' ) | grep 'IPAddress' | tail -n1 | awk -F'"' '{print $4}'
```