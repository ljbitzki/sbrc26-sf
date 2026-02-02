# Ataque "TCP RST Flood"

> Executa 10 segundos de pacotes TCP com a flag RST para `172.17.0.x` para a porta informada sem intervalo entre cada pacote

### Execução do ataque:
```
docker run --rm -d --name sbrc26-ataque-rst-flood sbrc26-ataque-rst-flood:latest "172.17.0.x" "8080"
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