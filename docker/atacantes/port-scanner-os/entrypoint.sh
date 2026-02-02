#!usr/bin/env bash
if [ "${#}" -eq 1 ]; then
	TARGET="${1}"
    /usr/bin/nmap -A -T4 "${TARGET}"
fi