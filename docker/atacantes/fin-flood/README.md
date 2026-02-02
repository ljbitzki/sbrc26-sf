# Ataque "TCP FIN Flood"

> Executa 10 segundos de pacotes TCP com a flag FIN para `172.17.0.x` na porta informada sem intervalo entre cada pacote

### Execução do ataque:
```
docker run --rm -d --name sbrc26-ataque-fin-flood sbrc26-ataque-fin-flood:latest "172.17.0.x" "8080"
```
#### Depende de (por exemplo): **`Servidor Web`**

#### IP do servidor `http-server`:
```
docker container inspect $( docker ps -a | grep 'sbrc26-ataque-http-server:latest' | awk '{print $NF}' ) | grep 'IPAddress' | tail -n1 | awk -F'"' '{print $4}'
```