FROM python:3.11-alpine
RUN apk add --no-cache git
RUN cd /tmp
RUN git clone https://github.com/gkbrk/slowloris.git
WORKDIR /tmp/slowloris
COPY atacantes/dos-http-slowloris/entrypoint.sh /tmp/slowloris/entrypoint.sh
RUN chmod +x /tmp/slowloris/entrypoint.sh
ENTRYPOINT ["/tmp/slowloris/entrypoint.sh"]