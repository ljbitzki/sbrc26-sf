#!/usr/bin/env bash

if [ "${#}" -ne 1 ]; then
    echo "Necessário passar a ação como parâmetro (parar, iniciar ou reiniciar)"
    echo "./servidores.sh parar ou ./servidores.sh iniciar ou ./servidores.sh reiniciar"
    exit 1
fi

if [ $( docker images --format table | grep -c 'sbrc26-servidor-' ) -ne 7 ]; then
    echo "Uma ou mais imagens de servidor está faltando. Executado o cd ~/sbrc26-sf/docker && ./build-images.sh para reconstruir as imagens."
    exit 1
fi

function PARAR {
    while read -r SERVER; do
        docker rm -f "${SERVER}"
    done < <( docker ps -a | grep 'sbrc26-servidor-' | awk '{print $1}' )
}

function INICIAR {
    if [ $( docker ps -a | grep -c 'sbrc26-servidor-http-server') -eq 0 ]; then
        docker run -d --rm --name sbrc26-servidor-http-server -p 8080:80 sbrc26-servidor-http-server:latest
    fi
    if [ $( docker ps -a | grep -c 'sbrc26-servidor-ssh-server') -eq 0 ]; then
        docker run -d --rm --name sbrc26-servidor-ssh-server -p 2222:22 sbrc26-servidor-ssh-server:latest
    fi
    if [ $( docker ps -a | grep -c 'sbrc26-servidor-smb-server') -eq 0 ]; then
        docker run -it -d --rm --name sbrc26-servidor-smb-server -p 139:139 -p 445:445 -p 137:137/udp -p 138:138/udp sbrc26-servidor-smb-server:latest  -g "log level = 3" -s "public;/share" -u "example2;badpass"
    fi
    if [ $( docker ps -a | grep -c 'sbrc26-servidor-mqtt-broker') -eq 0 ]; then
        docker run -d --rm --name sbrc26-servidor-mqtt-broker -p 1883:1883 -p 9001:9001 sbrc26-servidor-mqtt-broker:latest
    fi
    if [ $( docker ps -a | grep -c 'sbrc26-servidor-coap-server') -eq 0 ]; then
        docker run -d --rm --name sbrc26-servidor-coap-server -p 5683:5683 -p 5683:5683/udp sbrc26-servidor-coap-server:latest
    fi
    if [ $( docker ps -a | grep -c 'sbrc26-servidor-telnet-server') -eq 0 ]; then
        docker run -d --rm --name sbrc26-servidor-telnet-server -p 2323:23 sbrc26-servidor-telnet-server:latest
    fi
    if [ $( docker ps -a | grep -c 'sbrc26-servidor-ssl-heartbleed') -eq 0 ]; then
        docker run -d --rm --name sbrc26-servidor-ssl-heartbleed -p 8443:443 sbrc26-servidor-ssl-heartbleed:latest
    fi
}

case ${1} in
    parar)
        PARAR
        ;;
    iniciar)
        INICIAR
        ;;
    reiniciar)
        PARAR
        INICIAR
        ;;
    *)
        echo "Necessário passar a ação como parâmetro (parar, iniciar ou reiniciar)"
        ;;
esac