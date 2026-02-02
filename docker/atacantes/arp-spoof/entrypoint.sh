#!/bin/sh
if [ "${#}" -eq 2 ]; then
	GW="${1}"
    NETWORK="${2}"
    set -e
    timeout 5 ArpSpoof "${GW}" "${NETWORK}" -s -t 0.1
fi
