# Ataque "Ping Sweep"

> Executa pings para varrer uma rede `10.xx.xx.xx/xx` com timeout de 30ms para cada ping

### Execução do ataque:
```
docker run --rm -d --name sbrc26-ataque-ping-sweep sbrc26-ataque-ping-sweep:latest "10.20.30.0/20"
```