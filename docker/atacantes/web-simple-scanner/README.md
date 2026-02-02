# Ataque "Webserver Scanner"

> Executa scanner de vulnerabilidades conhecidas em webserver contra `http://172.17.0.x/` na porta informada

### Execução do ataque:
```
docker run --rm -d --name sbrc26-ataque-web-simple-scanner sbrc26-ataque-web-simple-scanner:latest "172.17.0.x" "8080"
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