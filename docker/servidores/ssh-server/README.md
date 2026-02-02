# Servidor "SSH"

> Servidor Alpine com serviço `SSH` openssh.

#### IP do servidor `SSH`:
```
docker container inspect $( docker ps -a | grep 'sbrc26-servidor-ssh-server:latest' | awk '{print $NF}' ) | grep 'IPAddress' | tail -n1 | awk -F'"' '{print $4}'
```

#### Logs `ssh`:
```
docker exec -it $( docker ps -a | grep 'sbrc26-servidor-ssh-server:latest' | awk '{print $NF}' ) cat /var/log/messages
```