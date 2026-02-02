FROM ubuntu:24.04
RUN apt update
RUN apt -f install
RUN apt install python3 python3-venv mosquitto-clients curl telnet expect ssh-client smbclient -y
RUN python3 -m venv venv
RUN . venv/bin/activate
RUN venv/bin/pip3 install --upgrade pip
RUN venv/bin/pip3 install aiocoap
COPY clientes/clients.sh /tmp/clients.sh
COPY clientes/smb-expect.sh /tmp/smb-expect.sh
COPY clientes/ssh-expect.sh /tmp/ssh-expect.sh
COPY clientes/telnet-expect.sh /tmp/telnet-expect.sh
COPY clientes/web-client.sh /tmp/web-client.sh
COPY clientes/coap-client.py /tmp/coap-client.py
RUN chmod +x /tmp/clients.sh
RUN chmod +x /tmp/smb-expect.sh
RUN chmod +x /tmp/ssh-expect.sh
RUN chmod +x /tmp/telnet-expect.sh
RUN chmod +x /tmp/web-client.sh
ENTRYPOINT ["/tmp/clients.sh"]