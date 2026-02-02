#!usr/bin/env bash
if [ "${#}" -eq 1 ]; then
	TARGET="${1}"
    /usr/bin/nmap -sV -O -A "${TARGET}"
fi