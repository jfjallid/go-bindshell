//go:build certauth

package main

import (
	_ "embed"
	"golang.org/x/crypto/ssh"
	"regexp"
	"strconv"
	"strings"
)

func init() {
	features["ca"] = getCerts
}

//go:embed ca.pub
var caPubKeyBytes []byte

//go:embed host
var hostPrivKeyBytes []byte

//go:embed host-cert.pub
var hostCertBytes []byte

//go:embed revokedCerts
var revocationListBytes []byte

var lineBreakRegExp = regexp.MustCompile(`\r?\n`)

func getCerts() (cert ssh.Signer, ca *ssh.PublicKey, crl map[string]int, err error) {

	// Read ca pubkey from disk to use for cert validation
	caPubKey, _, _, _, err := ssh.ParseAuthorizedKey(caPubKeyBytes)
	if err != nil {
		log.Errorf("%s\n", caPubKeyBytes)
		log.Criticalf("Failed to parse CA public key with error: %v\n", err)
		return
	}
	ca = &caPubKey

	// Read server privkey from disk
	hostPrivKey, err := ssh.ParsePrivateKey(hostPrivKeyBytes)
	if err != nil {
		log.Criticalf("Failed to parse Host private key with error: %v\n", err)
		return
	}

	// Load server certificate
	hostPubKey, _, _, _, err := ssh.ParseAuthorizedKey(hostCertBytes)
	if err != nil {
		log.Criticalf("Failed to parse host certificate with error: %v\n", err)
		return
	}

	// Create a signer from the server ssh cert and privkey
	cert, err = ssh.NewCertSigner(hostPubKey.(*ssh.Certificate), hostPrivKey)
	if err != nil {
		log.Criticalf("Failed to create certificate signer with error: %v\n", err)
		return
	}

	// Get list of revoked certificates
	crl = make(map[string]int)

	lines := lineBreakRegExp.Split(string(revocationListBytes), -1)
	for _, line := range lines {
		if line != "" {
			parts := strings.Split(line, ",")
			crl[parts[0]], err = strconv.Atoi(parts[1])
			if err != nil {
				log.Errorln(err)
			}
		}
	}

	log.Debugf("Using a certificate revocation map of: %v\n", crl)

	return
}
