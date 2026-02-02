#!/usr/bin/env bash
# curl --insecure https://host:8443
# curl http://host:8080
HOST=${1}
PORT=${2}

if [ "${PORT}" -eq 8443 ]; then
	PROTO="https"
	OPTS="--insecure"
else
	PROTO="http"
	OPTS=""
fi

curl ${OPTS} "${PROTO}://${HOST}:${PORT}"