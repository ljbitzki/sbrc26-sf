FROM ubuntu:24.04
RUN apt update
RUN apt install hping3 -y
COPY atacantes/rst-flood/entrypoint.sh /tmp/entrypoint.sh
RUN chmod +x /tmp/entrypoint.sh
ENTRYPOINT ["/tmp/entrypoint.sh"]
