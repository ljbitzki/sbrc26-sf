# Servidor "CoAP"

> Servidor Alpine com serviço `CoAP Server` com módulo aiocoap em Python.

#### IP do servidor `CoAP`:
```
docker container inspect $( docker ps -a | grep 'sbrc26-servidor-coap-server:latest' | awk '{print $NF}' ) | grep 'IPAddress' | tail -n1 | awk -F'"' '{print $4}'
```

#### Logs do servidor `CoAP`:
```
docker logs $( docker ps -a | grep 'sbrc26-servidor-coap-server:latest' | awk '{print $NF}' )
```