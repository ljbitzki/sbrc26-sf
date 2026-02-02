# Ataque "Bruteforce SSH"

> Executa 100 tentativas de login ssh na porta informada com senhas aleatórias em `root@172.17.0.x`.

### Execução do ataque:
```
docker run --rm -d --name sbrc26-ataque-ssh-bruteforce sbrc26-ataque-ssh-bruteforce:latest "172.17.0.x" "2222"
```
#### Depende de: **`Servidor SSH`**

#### IP do servidor `ssh`:
```
docker container inspect $( docker ps -a | grep 'sbrc26-ataque-ssh-server:latest' | awk '{print $NF}' ) | grep 'IPAddress' | tail -n1 | awk -F'"' '{print $4}'
```

#### Logs do servidor `ssh`:
```
docker exec -it $( docker ps -a | grep 'sbrc26-ataque-ssh-server:latest' | awk '{print $NF}' ) cat /var/log/messages
```