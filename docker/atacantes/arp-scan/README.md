# Ataque "ARP Scan"

> Executa enumeração de hosts através de ARP request "who-has" para a rede `172.17.0.x/yy`

### Execução do ataque:
```
docker run --rm -d --name sbrc26-ataque-arp-scan sbrc26-ataque-arp-scan:latest "172.17.0.x/yy"
```