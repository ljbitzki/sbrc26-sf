FROM ubuntu:24.04
RUN apt update
RUN apt install arp-scan -y
COPY atacantes/arp-scan/entrypoint.sh /tmp/entrypoint.sh
RUN chmod +x /tmp/entrypoint.sh
ENTRYPOINT ["/tmp/entrypoint.sh"]