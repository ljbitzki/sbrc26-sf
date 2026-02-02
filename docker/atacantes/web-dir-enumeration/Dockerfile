FROM ubuntu:24.04
RUN apt update
RUN apt install gobuster -y
COPY atacantes/web-dir-enumeration/directory-list-2.3-medium.txt /tmp/directory-list-2.3-medium.txt
COPY atacantes/web-dir-enumeration/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
