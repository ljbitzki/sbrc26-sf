FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /tmp

RUN set -eux; apt update
RUN apt install ca-certificates python3 python3-paramiko curl dnsutils samba-client openssh-client freerdp2-x11 snmp mosquitto-clients netcat-openbsd libcoap3-bin -y
    
RUN rm -rf /var/lib/apt/lists/*

COPY clientes/cliente-super/super-client.py /tmp/super-client.py
RUN chmod +x /tmp/super-client.py

ENTRYPOINT ["python3", "/tmp/super-client.py"]
