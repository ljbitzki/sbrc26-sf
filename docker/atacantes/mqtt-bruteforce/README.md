# Ataque "MQTT Brute-force"

> Executa ataque de força-bruta por dicionário de senhas contra `mqtt://172.17.0.y/`.

### Execução do ataque:
```
docker run --rm -d --name sbrc26-ataque-mqtt-bruteforce sbrc26-ataque-mqtt-bruteforce:latest "172.17.0.y"
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