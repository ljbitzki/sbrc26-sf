FROM ubuntu:24.04
RUN apt update
RUN apt install fping -y
COPY atacantes/ping-sweep/entrypoint.sh /tmp/entrypoint.sh
RUN chmod +x /tmp/entrypoint.sh
ENTRYPOINT ["/tmp/entrypoint.sh"]