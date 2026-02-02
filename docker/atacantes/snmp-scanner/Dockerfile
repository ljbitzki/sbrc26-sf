FROM ubuntu:24.04
RUN apt update
RUN apt install onesixtyone -y
COPY atacantes/snmp-scanner/common-snmp-community-strings.txt /tmp/common-snmp-community-strings.txt
COPY atacantes/snmp-scanner/entrypoint.sh /tmp/entrypoint.sh
RUN chmod +x /tmp/entrypoint.sh
ENTRYPOINT ["/tmp/entrypoint.sh"]
