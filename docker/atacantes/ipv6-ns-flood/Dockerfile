FROM ubuntu:24.04
RUN apt update
RUN apt install libpcap-dev libssl-dev -y
COPY atacantes/ipv6-ns-flood/flood_solicitate6 /usr/local/bin/flood_solicitate6
COPY atacantes/ipv6-ns-flood/entrypoint.sh /tmp/entrypoint.sh
RUN chmod +x /tmp/entrypoint.sh
RUN chmod +x /usr/local/bin/flood_solicitate6
ENTRYPOINT ["/tmp/entrypoint.sh"]
