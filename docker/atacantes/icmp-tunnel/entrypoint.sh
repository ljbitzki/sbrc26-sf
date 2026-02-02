#!/usr/bin/env bash
TARGET="${1}"
PORT="${2}"
function SSH() {
	timeout 1 ssh -p ${PORT} -l $( cat /dev/urandom | tr -dc "a-z0-9" | fold -w $(( 1 + RANDOM % 20 )) | head -n 1 ) 127.0.0.1
}
$( ptunnel-ng -p ${TARGET} -l ${PORT} ) &
sleep 1
for i in $( seq 1 100 ); do
	SSH &
	sleep 0.2
done
