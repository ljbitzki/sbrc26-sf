#!/usr/bin/env bash
if [ "${#}" -eq 2 ]; then
	TARGET="${1}"
    PORT="${2}"
    /tmp/ffuf -w /tmp/LFI-LFISuite-pathtotest.txt -u http://"${TARGET}:${PORT}/FUZZ" -fc 400
fi
