FROM python:3.11-alpine
RUN apk add --no-cache git
RUN git clone https://github.com/maksnowak/CoAPServer.git
WORKDIR /CoAPServer
COPY servidores/coap-server/requirements.txt requirements.txt
RUN pip3 install --upgrade pip
RUN pip3 install -r requirements.txt
EXPOSE 5683
ENTRYPOINT ["python", "-m", "coap_server", "--host", "0.0.0.0"]
