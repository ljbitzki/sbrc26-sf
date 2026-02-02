#!/bin/sh
if [ "${#}" -eq 2 ]; then
	TARGET="${1}"
    PORT="${2}"
    set -e
    exec python3 /tmp/sf.py -t "${TARGET}" -p "${PORT}" -c 500
fi