FROM ubuntu:24.04
RUN apt update
RUN apt install telnetd xinetd netcat-traditional -y
COPY servidores/telnet-server/telnet /etc/xinetd.d/telnet
COPY servidores/telnet-server/entrypoint.sh /tmp/entrypoint.sh
RUN chmod +x /tmp/entrypoint.sh
EXPOSE 23
ENTRYPOINT ["/tmp/entrypoint.sh"]