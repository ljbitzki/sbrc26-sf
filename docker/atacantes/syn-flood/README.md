# Ataque "TCP SYN Flood"

> Executa rajada de 500 pacotes TCP SYN para `172.17.0.x` na porta informada sem intervalo entre pacotes

### Execução do ataque:
```
docker run --rm -d --name sbrc26-ataque-syn-flood sbrc26-ataque-syn-flood:latest "172.17.0.x" "8080"
```
#### Depende de (por exemplo): **`Servidor Web`**

#### IP do servidor `http-server`:
```
docker container inspect $( docker ps -a | grep 'sbrc26-ataque-http-server:latest' | awk '{print $NF}' ) | grep 'IPAddress' | tail -n1 | awk -F'"' '{print $4}'
```

#### Logs do servidor `http-server`:
```
docker logs $( docker ps -a | grep 'sbrc26-ataque-http-server:latest' | awk '{print $NF}' )
```