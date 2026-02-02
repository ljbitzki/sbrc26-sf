FROM ubuntu:24.04
RUN apt update
RUN apt install libpcap-dev libssl-dev -y
COPY atacantes/ipv6-ra-flood/flood_router6 /usr/local/bin/flood_router6
COPY atacantes/ipv6-ra-flood/entrypoint.sh /tmp/entrypoint.sh
RUN chmod +x /tmp/entrypoint.sh
RUN chmod +x /usr/local/bin/flood_router6
ENTRYPOINT ["/tmp/entrypoint.sh"]
