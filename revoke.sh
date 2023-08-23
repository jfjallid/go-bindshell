#!/bin/bash
# Utility to revoke ssh client certificates for the SSH bindshell.
# Due to missing functionality of reading and handling KRLs in Golangs ssh package
# The revocation check is performed by checking a client certificate's fingerprint and
# serial number against a list of revoked certificates.
# The purpose of this utility is to extract fingerprint and serial from a certificate
# and append it to the list of revoked certificates

cert=$1

fingerprint=$(ssh-keygen -L -f ${cert} 2>/dev/null | grep Public | awk '{print $4}')
serial=$(ssh-keygen -L -f ${cert} 2>/dev/null | grep Serial | awk '{print $2}')
subject=$(ssh-keygen -L -f ${cert} 2>/dev/null | grep Key | awk '{print $3}')

if [[ $fingerprint != "" ]] && [[ $serial != "" ]] && [[ $subject != "" ]]; then
    echo "Revoking certificate issued to ${subject} with fingerprint ${fingerprint}, serial: ${serial}"
    echo "${fingerprint},${serial}" >> revokedCerts
else
    echo "Failed to parse certificate"
fi
