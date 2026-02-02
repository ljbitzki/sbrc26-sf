FROM ubuntu:24.04
RUN apt update
RUN apt install hydra -y
COPY atacantes/ssh-bruteforce/entrypoint.sh /tmp/entrypoint.sh
RUN chmod +x /tmp/entrypoint.sh
ENTRYPOINT ["/tmp/entrypoint.sh"]