#!/usr/bin/env bash
if [ "${#}" -eq 1 ]; then
	TARGET="${1}"
    for i in $( seq 1 1000 ); do
        mosquitto_pub -h ${TARGET} -i mosq_pub1 -t "Test ${i}" -m "Message with ID: ${i}"
    done
fi