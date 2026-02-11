#!/usr/bin/env bash
DOMAIN=$( cat /dev/urandom | tr -dc "0-9a-fA-F" | fold -w 8 | head -n 1 )
DNS_SERVERS=("1.1.1.1" "1.0.0.1" "8.8.8.8" "8.8.4.4" "9.9.9.9" "149.112.112.112" "76.76.19.19")
LENGHT=${#DNS_SERVERS[@]}
DOMAIN=$( cat /dev/urandom | tr -dc "0-9a-fA-F" | fold -w 8 | head -n 1 )
function DNS_RESOLVE() {
  DNS="${DNS_SERVERS[$((RANDOM % LENGHT))]}"
  RANGE=$(( 12 + $RANDOM % 50 ))
  SUBDOMAIN=$( cat /dev/urandom | tr -dc "0-9a-fA-F" | fold -w "${RANGE}" | head -n 1 )
  dig @$DNS +time=1 +tries=1 +short "${SUBDOMAIN}.${DOMAIN}.com" 2>&1 | head -1
}
for i in $( seq 1 200 ); do
  DNS_RESOLVE &
  sleep 0.2
done