FROM ubuntu:24.04
RUN apt update
RUN apt install mosquitto-clients -y
COPY atacantes/mqtt-publisher/entrypoint.sh /tmp/entrypoint.sh
RUN chmod +x /tmp/entrypoint.sh
ENTRYPOINT ["/tmp/entrypoint.sh"]
