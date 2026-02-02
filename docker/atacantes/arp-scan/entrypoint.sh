#!/usr/bin/env bash
if [ "${#}" -eq 1 ]; then
	TARGET="${1}"
    arp-scan "${TARGET}"
fi
