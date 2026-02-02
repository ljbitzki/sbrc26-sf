# Ataque "Simple HTTP DoS"

> Executa rajada de 200 acessos em subdirtórios aleatórios de `http://172.17.0.x/` na porta ionformada.

### Execução do ataque:
```
docker run --rm -d --name sbrc26-ataque-dos-http-simple sbrc26-ataque-dos-http-simple:latest "172.17.0.x" "8080"
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