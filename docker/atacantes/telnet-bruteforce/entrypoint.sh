#!/usr/bin/env bash
if [ "${#}" -eq 2 ]; then
	TARGET="${1}"
	PORT="${2}"
	PWDS="/tmp/pass.lst"
	for i in $( seq 1 100 ); do
		cat /dev/urandom | tr -dc "a-zA-Z0-9" | fold -w 24 | head -n 1 >> "${PWDS}"
	done
	/usr/bin/hydra -l root -P ${PWDS} telnet://${TARGET} -s 2323
fi