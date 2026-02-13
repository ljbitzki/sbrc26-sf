#!/usr/bin/env bash

if [ "${#}" -ne 1 ]; then
    echo "Necessário passar a ação como parâmetro (reiniciar)"
    echo "./ambiente.sh reiniciar"
    exit 1
fi

function REINICIAR {
    SLPID=$( sudo ps aux | grep 'streamlit' | grep -v grep | awk '{print $2}' )
    if [[ -z "${SLPID}" ]]; then
        ./servidores.sh reiniciar
        source .venv/bin/activate
        streamlit run ferramenta.py --theme.base="dark" --server.headless true &
    else
        sudo kill "${SLPID}"
        ./servidores.sh reiniciar
        source .venv/bin/activate
        streamlit run ferramenta.py --theme.base="dark" --server.headless true &
    fi
}

function PARAR {
	./servidores.sh parar
	if [[ -n $( which deactivate ) ]]; then
		deactivate
	fi
	SLPID=$( sudo ps aux | grep 'streamlit' | grep -v grep | awk '{print $2}' )
	if [[ -n "${SLPID}" ]]; then
		kill "${SLPID}"
	fi
}

case "${1}" in
    reiniciar|iniciar)
        REINICIAR
        ;;
    parar)
	    PARAR
	    ;;
    *)
        echo "Necessário passar a ação como parâmetro (reiniciar)"
        ;;
esac
