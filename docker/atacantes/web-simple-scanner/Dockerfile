FROM ubuntu:24.04
RUN apt update
RUN apt install nikto -y
COPY atacantes/web-simple-scanner/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
