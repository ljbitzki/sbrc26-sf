#!/usr/bin/env bash

. /venv/bin/activate

WEB_SERVER="${1}"
SSH_SERVER="${2}"
SMB_SERVER="${3}"
MQTT_SERVER="${4}"
COAP_SERVER="${5}"
TELNET_SERVER="${6}"
SSL_SERVER="${7}"

function WEB() {
    echo "Executando HTTP"
    /tmp/web-client.sh "${WEB_SERVER}" "80"
}

function SSH() {
    echo "Executando SSH"
    /tmp/ssh-expect.sh "client" "${SSH_SERVER}" "22"
}

function SMB() {
     echo "Executando SMB"
     /tmp/smb-expect.sh "client" "badpass" "${SMB_SERVER}"
}

function MQTT() {
    RANDNUM=$(( (RANDOM % 9999) + 1 ))
    echo "Executando MQTT"
    mosquitto_pub -h "${MQTT_SERVER}" -i mosq_pub1 -t "Client test" -m "Message with ID: ${RANDNUM}"
}

function COAP() {
    RANDNUM=$(( (RANDOM % 9999) + 1 ))
    echo "Executando COAP"
    /venv/bin/python3 /tmp/coap-client.py "${COAP_SERVER}" "${RANDNUM}"
}

function TELNET() {
    echo "Executando TELNET"
    /tmp/telnet-expect.sh "${TELNET_SERVER}" "23"
}

function SSL() {
    echo "Executando HTTPS"
    /tmp/web-client.sh "${SSL_SERVER}" "443"
}

CLIENTS=("WEB" "SSH" "SMB" "MQTT" "COAP" "TELNET" "SSL")
LENGHT=${#CLIENTS[@]}
function PICK() {
  CLIENT="${CLIENTS[$((RANDOM % LENGHT))]}"
  $CLIENT
}

while true; do
    SEC=$(( 1 + $RANDOM % 5 ))
    CSEC=$(( 1 + $RANDOM % 5 ))
    sleep "${SEC}.${CSEC}"
    PICK &
done 