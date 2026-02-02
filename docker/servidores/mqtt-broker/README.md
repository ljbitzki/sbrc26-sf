# Servidor "MQTT Broker"

> Servidor Alpine com serviço `MQTT Broker` Eclipse Mosquitto.

#### IP do servidor `mqtt-broker`:
```
docker container inspect $( docker ps -a | grep 'sbrc26-servidor-mqtt-broker:latest' | awk '{print $NF}' ) | grep 'IPAddress' | tail -n1 | awk -F'"' '{print $4}'
```

#### Logs do servidor `mqtt-broker`:
```
docker logs $( docker ps -a | grep 'sbrc26-servidor-mqtt-broker:latest' | awk '{print $NF}' )
```