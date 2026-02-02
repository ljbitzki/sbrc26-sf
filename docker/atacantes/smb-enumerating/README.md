# Ataque "SMB Enumerating"

> Executa enumeração de diretórios e vulnerabilidades de compartilhamentos samba contra `172.17.0.z`.

### Execução do ataque:
```
docker run --rm -d --name sbrc26-ataque-smb-enumerating sbrc26-ataque-smb-enumerating:latest "172.17.0.x"
```
#### Depende de: **`Servidor Samba`**

#### IP do servidor `smb-server`:
```
docker container inspect $( docker ps -a | grep 'sbrc26-ataque-smb-server:latest' | awk '{print $NF}' ) | grep 'IPAddress' | tail -n1 | awk -F'"' '{print $4}'
```

#### Logs do servidor `smb-server`:
```
docker logs $( docker ps -a | grep 'sbrc26-ataque-smb-server:latest' | awk '{print $NF}' )
```