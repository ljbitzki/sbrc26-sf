# Ataque "IDOR (Insecure Direct Object Reference) - Path Traversal"

> Executa ataque de tentativa de acesso a arquivos locais via webserver, através de _wordlist_, contra `http://172.17.0.x/` na porta informada

### Execução do ataque:
```
docker run --rm -d --name sbrc26-ataque-web-idor-path-traversal sbrc26-ataque-idor-path-traversal:latest "http://172.17.0.x/" "8080"
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