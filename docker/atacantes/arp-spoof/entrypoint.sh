#!/bin/sh
if [ "${#}" -eq 2 ]; then
	GW="${1}"
    NETWORK="${2}"
    set -e
    ArpSpoof "${GW}" "${NETWORK}" -s -t 0.1
fi
