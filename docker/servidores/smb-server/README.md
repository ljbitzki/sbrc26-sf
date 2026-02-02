# Servidor "SMB Server"

> Servidor Alpine com serviço `SMB` Samba.

#### IP do servidor `smb-server`:
```
docker container inspect $( docker ps -a | grep 'sbrc26-servidor-smb-server:latest' | awk '{print $NF}' ) | grep 'IPAddress' | tail -n1 | awk -F'"' '{print $4}'
```

#### Logs do servidor `smb-server`:
```
docker logs $( docker ps -a | grep 'sbrc26-servidor-smb-server:latest' | awk '{print $NF}' )
```