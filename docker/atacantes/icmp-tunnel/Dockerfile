FROM ubuntu:24.04
RUN apt update
RUN apt install ptunnel-ng openssh-client -y
COPY atacantes/icmp-tunnel/entrypoint.sh /tmp/entrypoint.sh
COPY atacantes/icmp-tunnel/known_hosts /root/.ssh/known_hosts
RUN chmod +x /tmp/entrypoint.sh
ENTRYPOINT ["/tmp/entrypoint.sh"]
