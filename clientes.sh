#!/usr/bin/env bash

if [ "${#}" -ne 1 ]; then
    echo "Necessário passar a ação como parâmetro (parar ou iniciar)"
    echo "./clientes.sh parar ou ./clientes.sh iniciar"
    exit 1
fi

if [ $( docker images --format table | grep -c 'sbrc26-clientes' ) -ne 1 ]; then
    echo "Uma ou mais imagem(ns) de servidor(es) está(ão) faltando. Certifique-se de ter executado o criar-imagens.sh conforme a documentação."
    exit 1
fi

function PARAR {
    while read -r CLIENTE; do
        docker rm -f "${CLIENTE}"
    done < <( docker ps -a | grep 'sbrc26-cliente-' | awk '{print $1}' )
}

function INICIAR {
    if [ $( docker ps -a | grep -c 'sbrc26-servidor-') -eq 7 ]; then
        WEB_S=$( docker container inspect $( docker ps -a | grep 'sbrc26-servidor-http-server' | awk '{print $NF}' ) | grep 'IPAddress' | tail -n1 | awk -F'"' '{print $4}' )
        SSH_S=$( docker container inspect $( docker ps -a | grep 'sbrc26-servidor-ssh-server' | awk '{print $NF}' ) | grep 'IPAddress' | tail -n1 | awk -F'"' '{print $4}' )
        SMB_S=$( docker container inspect $( docker ps -a | grep 'sbrc26-servidor-smb-server' | awk '{print $NF}' ) | grep 'IPAddress' | tail -n1 | awk -F'"' '{print $4}' )
        MQTT_S=$( docker container inspect $( docker ps -a | grep 'sbrc26-servidor-mqtt-broker' | awk '{print $NF}' ) | grep 'IPAddress' | tail -n1 | awk -F'"' '{print $4}' )
        COAP_S=$( docker container inspect $( docker ps -a | grep 'sbrc26-servidor-coap-server' | awk '{print $NF}' ) | grep 'IPAddress' | tail -n1 | awk -F'"' '{print $4}' )
        TELNET_S=$( docker container inspect $( docker ps -a | grep 'sbrc26-servidor-telnet-server' | awk '{print $NF}' ) | grep 'IPAddress' | tail -n1 | awk -F'"' '{print $4}' )
        SSL_S=$( docker container inspect $( docker ps -a | grep 'sbrc26-servidor-ssl-heartbleed' | awk '{print $NF}' ) | grep 'IPAddress' | tail -n1 | awk -F'"' '{print $4}' )
        NUM_CLIENT=$( docker ps -a | grep 'sbrc26-cliente-' | wc -l )
        NEXT=$(( NUM_CLIENT + 1 ))
        docker run -d --rm --name sbrc26-cliente-${NEXT} sbrc26-clientes:latest "${WEB_S}" "${SSH_S}" "${SMB_S}" "${MQTT_S}" "${COAP_S}" "${TELNET_S}" "${SSL_S}"
    else
        echo "Um ou mais servidores não estão em execução. Certifique-se de que todos estejam operando (execute ./servidores.sh reiniciar)"
        exit 1
    fi
}

case ${1} in
    parar)
        PARAR
        ;;
    iniciar)
        INICIAR
        ;;
    *)
        echo "Necessário passar a ação como parâmetro (parar ou iniciar)"
        ;;
esac