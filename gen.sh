#!/bin/bash
# A utility to create certificates signed by a CA and with various permissions.
# This script is far from perfect but could serve as an inspiration on how to
# generate new certificates and keep the serial number synchronized.

saveSerial() {
    echo "Saving serial number"
    echo $serial > serial
}

trap 'saveSerial' ERR

# Read current certificate serial number
serial=$(cat serial)

# Only allow spawning a shell and command execution but without PTY
#ssh-keygen -z ${serial} -s ./ca -I user_identifier -n user,test -V +7d -O clear id_rsa.pub
#serial=$(( $serial + 1 ))

# shell, command + PTY
#ssh-keygen -z ${serial} -s ./ca -I user_identifier -n user,test -V +7d -O clear -O permit-pty id_rsa.pub
#serial=$(( $serial + 1 ))

# shell, command, portforwarding
#ssh-keygen -z ${serial} -s ./ca -I user_identifier -n user,test -V +7d -O clear -O permit-port-forwarding -O permit-pty id_rsa.pub
#serial=$(( $serial + 1 ))

#ssh-keygen -z ${serial} -s ./ca -I user_identifier -n user,test -V +7d -O clear -O no-port-forwarding -O no-pty id_rsa.pub
#serial=$(( $serial + 1 ))

# Only portforwarding
ssh-keygen -z ${serial} -s ./ca -I user@domain.local -n user -V +7d -O clear -O permit-port-forwarding user-id_rsa.pub
serial=$(( $serial + 1 ))

ssh-keygen -z ${serial} -s ./ca -I other@domain.local -n other -V +7d -O clear -O permit-port-forwarding other-id_rsa.pub
serial=$(( $serial + 1 ))

ssh-keygen -z ${serial} -s ./ca -I server@domain.local host
serial=$(( $serial + 1 ))

saveSerial
