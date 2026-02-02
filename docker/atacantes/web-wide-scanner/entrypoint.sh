#!/bin/sh
if [ "${#}" -eq 2 ]; then
	TARGET="${1}"
    PORT="${2}"
    set -e
    exec python3 /spiderfoot-4.0/sf.py -s "${TARGET}:${PORT}"
fi
