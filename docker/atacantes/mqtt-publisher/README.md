# Ataque "MQTT Publish Flood"

> Executa rajada de 1000 publicações contra `mqtt://172.17.0.y/`

### Execução do ataque:
```
docker run --rm -d --name sbrc26-ataque-mqtt-publisher sbrc26-ataque-mqtt-publisher:latest "172.17.0.y"
```
#### Depende de: **`MQTT Broker`**

#### IP do servidor `mqtt-broker`:
```
docker container inspect $( docker ps -a | grep 'sbrc26-ataque-mqtt-broker:latest' | awk '{print $NF}' ) | grep 'IPAddress' | tail -n1 | awk -F'"' '{print $4}'
```

#### Logs do servidor `mqtt-broker`:
```
docker logs $( docker ps -a | grep 'sbrc26-ataque-mqtt-broker:latest' | awk '{print $NF}' )
```