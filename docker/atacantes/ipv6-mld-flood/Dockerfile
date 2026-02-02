FROM ubuntu:24.04
RUN apt update
RUN apt install libpcap-dev libssl-dev -y
COPY atacantes/ipv6-mld-flood/flood_mld6 /usr/local/bin/flood_mld6
COPY atacantes/ipv6-mld-flood/entrypoint.sh /tmp/entrypoint.sh
RUN chmod +x /tmp/entrypoint.sh
RUN chmod +x /usr/local/bin/flood_mld6
ENTRYPOINT ["/tmp/entrypoint.sh"]
