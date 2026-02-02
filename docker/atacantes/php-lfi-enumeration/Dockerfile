FROM python:3.11-alpine
WORKDIR /tmp
COPY atacantes/php-lfi-enumeration/lfi.py /tmp/lfi.py
COPY atacantes/php-lfi-enumeration/requirements.txt /tmp/requirements.txt
COPY atacantes/php-lfi-enumeration/LFISuite-pathtotest.txt /tmp/LFISuite-pathtotest.txt
COPY atacantes/php-lfi-enumeration/entrypoint.sh /tmp/entrypoint.sh
RUN pip3 install --upgrade pip
RUN pip3 install -r /tmp/requirements.txt
RUN chmod +x /tmp/entrypoint.sh
ENTRYPOINT ["/tmp/entrypoint.sh"]