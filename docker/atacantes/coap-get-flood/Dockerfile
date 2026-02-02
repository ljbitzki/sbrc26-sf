FROM python:3.11-alpine
RUN pip3 install --upgrade pip
RUN pip3 install aiocoap
WORKDIR /tmp
COPY atacantes/coap-get-flood/entrypoint.sh /tmp/entrypoint.sh
COPY atacantes/coap-get-flood/client.py /tmp/client.py
RUN chmod +x /tmp/entrypoint.sh
ENTRYPOINT ["/tmp/entrypoint.sh"]