#!/bin/sh
if [ "${#}" -eq 1 ]; then
	TARGET="${1}"
    set -e
    exec python3 /tmp/client.py "${TARGET}"
fi
