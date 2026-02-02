# Servidor "HTTP"

> Servidor `Web` com Damn Vulnerable Web Application (DVWA)

#### IP do servidor `HTTP`:
```
docker container inspect $( docker ps -a | grep 'sbrc26-servidor-http-server:latest' | awk '{print $NF}' ) | grep 'IPAddress' | tail -n1 | awk -F'"' '{print $4}'
```

#### Logs `HTTP`:
```
docker exec -it $( docker ps -a | grep 'sbrc26-servidor-http-server:latest' | awk '{print $NF}' ) cat /var/log/messages
```