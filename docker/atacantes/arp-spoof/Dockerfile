FROM python:3.11-alpine
RUN apk add coreutils
WORKDIR /tmp/arpspoof
RUN pip3 install --upgrade pip
RUN pip3 install ArpSpoof
COPY atacantes/arp-spoof/entrypoint.sh /tmp/arpspoof/entrypoint.sh
RUN chmod +x /tmp/arpspoof/entrypoint.sh
ENTRYPOINT ["/tmp/arpspoof/entrypoint.sh"]