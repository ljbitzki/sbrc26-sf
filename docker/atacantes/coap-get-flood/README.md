# Ataque "CoAP GET Flood"

> Executa rajada de 1000 requisições GET contra `mqtt://172.17.0.w/`

### Execução do ataque:
```
docker run --rm -d --name sbrc26-ataque-coap-get-flood sbrc26-ataque-coap-get-flood:latest "172.17.0.w"
```
#### Depende de: **`Servidor CoAP`**

#### IP do servidor `CoAP`:
```
docker container inspect $( docker ps -a | grep 'sbrc26-ataque-coap-server:latest' | awk '{print $NF}' ) | grep 'IPAddress' | tail -n1 | awk -F'"' '{print $4}'
```

#### Logs do servidor `CoAP`:
```
docker logs $( docker ps -a | grep 'sbrc26-ataque-coap-server:latest' | awk '{print $NF}' )
```