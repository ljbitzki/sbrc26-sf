#!usr/bin/env bash
if [ "${#}" -eq 2 ]; then
	TARGET="${1}"
    PORT="${2}"
    /usr/bin/gobuster dir -u "http://${TARGET}:${PORT}" -w /tmp/directory-list-2.3-medium.txt -x php,html,js,txt,asp,aspx,jsp
fi
