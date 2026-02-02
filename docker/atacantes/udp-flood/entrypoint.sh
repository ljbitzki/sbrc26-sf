#!/usr/bin/env bash
if [ "${#}" -eq 2 ]; then
	TARGET="${1}"
    PORT="${2}"
    timeout 5 hping3 -2 -p "${PORT}" --flood "${TARGET}"
fi
