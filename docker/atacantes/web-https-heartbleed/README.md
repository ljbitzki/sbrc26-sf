# Ataque "SSL HeartBleed"

> Executa 200 requisições contra `http://172.17.0.x/` vulnerável ao bug HeartBleed, na porta informada.

### Execução do ataque:
```
docker run --rm -d --name sbrc26-ataque-web-https-heartbleed sbrc26-ataque-web-https-heartbleed:latest `http://172.17.0.x/ "8443"
```

#### Depende de: **`SSL Heartbleed`**

#### IP do servidor `ssl-heartbleed`:
```
docker container inspect $( docker ps -a | grep 'sbrc26-ataque-ssl-heartbleed:latest' | awk '{print $NF}' ) | grep 'IPAddress' | tail -n1 | awk -F'"' '{print $4}'
```

#### Logs do servidor `ssl-heartbleed`:
```
docker logs $( docker ps -a | grep 'sbrc26-ataque-ssl-heartbleed:latest' | awk '{print $NF}' )
```