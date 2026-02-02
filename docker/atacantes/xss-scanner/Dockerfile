FROM hahwul/dalfox
COPY atacantes/xss-scanner/XSS-payloadbox.txt /app/XSS-payloadbox.txt
COPY atacantes/xss-scanner/entrypoint.sh /tmp/entrypoint.sh
RUN chmod +x /app/dalfox
RUN chmod +x /tmp/entrypoint.sh
ENTRYPOINT ["/tmp/entrypoint.sh"]
