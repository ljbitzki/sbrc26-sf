# Ataque "SNMP Scanner"

> Executa consultas SNMP em todos os hosts de uma rede, utilizando _wordlist_ de comunidades. `192.168.0.0/24` será utilizada se nenhuma rede for passada como parâmetro.

### Execução do ataque:
```
docker run --rm -d --name sbrc26-ataque-snmp-scanner sbrc26-ataque-snmp-scanner:latest "192.168.xx.xx/xx"
```
