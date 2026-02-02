FROM ubuntu:24.04
RUN apt update
RUN apt install dnsutils -y
COPY atacantes/dns-tunneling/entrypoint.sh /tmp/entrypoint.sh
RUN chmod +x /tmp/entrypoint.sh
ENTRYPOINT ["/tmp/entrypoint.sh"]
