#!/bin/sh
if [ "${#}" -eq 2 ]; then
	TARGET="${1}"
    PORT="${2}"
    set -e
    exec python3 /slowloris/slowloris.py "${TARGET}:${PORT}"
fi