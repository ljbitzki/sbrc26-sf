#!/usr/bin/expect
# smb-expect.sh "example2" "badpass" "172.17.0.4"
set username [lindex $argv 0]
set password [lindex $argv 1]
set host [lindex $argv 2]

spawn /usr/bin/smbclient "-L //$host/share -U username"

expect "Password for" { send "$password\n" }