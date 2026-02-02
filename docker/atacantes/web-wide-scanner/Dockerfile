FROM python:3.11-alpine
RUN apk add --no-cache tar wget
RUN wget https://github.com/smicallef/spiderfoot/archive/v4.0.tar.gz && tar zxf v4.0.tar.gz
WORKDIR /spiderfoot-4.0
COPY atacantes/web-wide-scanner/requirements.txt requirements.txt
RUN pip3 install --upgrade pip
RUN pip3 install -r requirements.txt
COPY atacantes/web-wide-scanner/entrypoint.sh /spiderfoot-4.0/entrypoint.sh
RUN chmod +x /spiderfoot-4.0/entrypoint.sh
ENTRYPOINT ["/spiderfoot-4.0/entrypoint.sh"]