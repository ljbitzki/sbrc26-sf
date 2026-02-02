# Ataque "Cross-Site Scripting Scanner (XSS)"

> Executa uma varredura automatizada e análise de falhas de parâmetros suscetíveis a XSS contra `172.17.0.x` na porta informada

### Execução do ataque:
```
docker run --rm -d --name sbrc26-ataque-xss-scanner sbrc26-ataque-xss-scanner:latest "172.17.0.x" "8080"
```

#### Depende de: **`Servidor Web`**

#### IP do servidor `Web`:
```
docker container inspect $( docker ps -a | grep 'sbrc26-ataque-http-server:latest' | awk '{print $NF}' ) | grep 'IPAddress' | tail -n1 | awk -F'"' '{print $4}'
```

#### Logs do servidor `Web`:
```
docker logs $( docker ps -a | grep 'sbrc26-ataque-http-server:latest' | awk '{print $NF}' )
```
