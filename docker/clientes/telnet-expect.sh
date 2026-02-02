#!/usr/bin/expect
# telnet-expect.sh "lalala" "172.17.0.7" "23"
set timeout 1
set host [lindex $argv 0]
set port [lindex $argv 1]

spawn telnet $host $port
expect "*login:" { send "\x18" }
