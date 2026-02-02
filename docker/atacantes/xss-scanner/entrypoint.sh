#!/usr/bin/env bash
if [ "${#}" -eq 2 ]; then
	TARGET="${1}"
	PORT="${2}"
	/app/dalfox url http://${TARGET}:${PORT}/login.php\?cat\=123\&artist\=123\&asdf\=ff -b https://192.168.0.123 --custom-payload /app/XSS-payloadbox.txt
fi
