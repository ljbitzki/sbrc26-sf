FROM ubuntu:24.04
COPY atacantes/idor-url-parameter/ffuf /tmp/ffuf
COPY atacantes/idor-url-parameter/all-dirs.txt /tmp/all-dirs.txt
COPY atacantes/idor-url-parameter/entrypoint.sh /tmp/entrypoint.sh
RUN chmod +x /tmp/ffuf
RUN chmod +x /tmp/entrypoint.sh
ENTRYPOINT ["/tmp/entrypoint.sh"]