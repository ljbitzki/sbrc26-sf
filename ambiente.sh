#!/usr/bin/env bash

if [ "${#}" -ne 1 ]; then
    echo "Necessário passar a ação como parâmetro (reiniciar)"
    echo "./ambiente.sh reiniciar"
    exit 1
fi

function REINICIAR {
    SLPID=$( sudo ps aux | grep 'streamlit' | grep -v grep | awk '{print $2}' )
    if [ -z "${SLPID}" ]; then
        ./servidores.sh reiniciar
        source .venv/bin/activate
        streamlit run ferramenta.py --theme.base="dark" &
    else
        sudo kill "${SLPID}"
        ./servidores.sh reiniciar
        source .venv/bin/activate
        streamlit run ferramenta.py --theme.base="dark" &
    fi
}

case "${1}" in
    reiniciar)
        REINICIAR
        ;;
    *)
        echo "Necessário passar a ação como parâmetro (reiniciar)"
        ;;
esac
