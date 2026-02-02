FROM ubuntu:24.04
COPY atacantes/idor-path-traversal/ffuf /tmp/ffuf
COPY atacantes/idor-path-traversal/LFI-LFISuite-pathtotest.txt /tmp/LFI-LFISuite-pathtotest.txt
COPY atacantes/idor-path-traversal/entrypoint.sh /tmp/entrypoint.sh
RUN chmod +x /tmp/ffuf
RUN chmod +x /tmp/entrypoint.sh
ENTRYPOINT ["/tmp/entrypoint.sh"]