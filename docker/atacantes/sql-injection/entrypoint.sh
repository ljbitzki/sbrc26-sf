#!/bin/sh
if [ "${#}" -eq 2 ]; then
	TARGET="${1}"
    PORT="${2}"
    set -e
    exec python /sqlmap/sqlmap.py -u "${TARGET}:${PORT}" --batch --level=3
fi
