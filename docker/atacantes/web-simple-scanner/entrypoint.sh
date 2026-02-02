#!usr/bin/env bash
if [ "${#}" -eq 2 ]; then
	TARGET="${1}"
    PORT="${2}"
    /usr/bin/nikto -Cgidirs=all -h "http://${TARGET}:${PORT}" >/dev/null 2>&1
fi