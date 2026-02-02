#!/usr/bin/env bash
if [ "${#}" -eq 2 ]; then
	TARGET="${1}"
    PORT="${2}"
    /tmp/ffuf -w /tmp/all-dirs.txt -u http://"${TARGET}:${PORT}"/login.php?valid_name=FUZZ -fc 401
fi
