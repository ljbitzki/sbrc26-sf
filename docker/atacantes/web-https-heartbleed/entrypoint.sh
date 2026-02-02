#!usr/bin/env bash
if [ "${#}" -eq 2 ]; then
	TARGET="${1}"
	PORT="${2}"
	for i in {1..200}; do
		python3 /tmp/ssltest.py "${TARGET}" -p "${PORT}" | tail -n1
	done
fi
