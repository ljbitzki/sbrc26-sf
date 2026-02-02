#!/usr/bin/env bash
if [ "${#}" -eq 1 ]; then
	TARGET="${1}"
else
    TARGET="192.168.0.0/24"
fi
onesixtyone "${TARGET}" -c /tmp/common-snmp-community-strings.txt
