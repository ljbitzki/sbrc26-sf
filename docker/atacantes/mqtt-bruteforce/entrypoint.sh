#!/bin/sh
if [ "${#}" -eq 1 ]; then
	TARGET="${1}"
    set -e
    exec python3 /ralmqtt/ralmqtt.py -m bruteforce -a "${TARGET}" -w /ralmqtt/passwords.txt
fi