FROM python:3.11-alpine
RUN apk add --no-cache git
RUN git clone https://github.com/polo-le-rigolo/ralmqtt
WORKDIR /ralmqtt
RUN pip3 install --upgrade pip
RUN pip3 install -r requirements.txt
COPY atacantes/mqtt-bruteforce/entrypoint.sh /ralmqtt/entrypoint.sh
RUN chmod +x /ralmqtt/entrypoint.sh
ENTRYPOINT ["/ralmqtt/entrypoint.sh"]