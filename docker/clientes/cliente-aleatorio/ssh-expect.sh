#!/usr/bin/expect
# ssh-expect.sh "lalala" "172.17.0.3" "22"
set timeout 1
set username [lindex $argv 0]
set host [lindex $argv 1]
set port [lindex $argv 2]

spawn ssh -o StrictHostKeyChecking=no $username@$host -p $port
expect "password:" { send "\x18" }
expect "Are you sure you want to continue connecting" { send "no\n" }