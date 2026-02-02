# Ataque "Port Vulnerabilities Scanner"

> Executa o nmap no modo reconhecimento via plugin com módulo de scan de vulnerabilidades contra `172.17.0.x`

### Execução do ataque:
```
docker run --rm -d --name sbrc26-ataque-port-scanner-vulnerabilities sbrc26-ataque-port-scanner-vulnerabilities:latest "172.17.0.x"
```
#### Depende de: **`Servidor Web`**

#### IP do servidor `http-server`:
```
docker container inspect $( docker ps -a | grep 'sbrc26-ataque-http-server:latest' | awk '{print $NF}' ) | grep 'IPAddress' | tail -n1 | awk -F'"' '{print $4}'
```

#### Logs do servidor `http-server`:
```
docker logs $( docker ps -a | grep 'sbrc26-ataque-http-server:latest' | awk '{print $NF}' )
```