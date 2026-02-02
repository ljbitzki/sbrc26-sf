# Ataque "SlowLoris HTTP DoS"

> Executa ataque de manutenção de 150 sockets contra `http://172.17.0.x/` na porta informada utilizando implementação SlowLoris.

### Execução do ataque:
```
docker run --rm -d --name sbrc26-ataque-dos-http-slowloris sbrc26-ataque-dos-http-slowloris:latest "172.17.0.x" "8080"
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