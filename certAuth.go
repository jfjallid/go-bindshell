//go:build certauth

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	_ "embed"
	"encoding/pem"

	"golang.org/x/crypto/ssh"
)

func init() {
	features["ca"] = genCAHostKey
}

//go:embed ca
var caPrivKeyBytes []byte

func genCAHostKey() (cert ssh.Signer, ca *ssh.PublicKey, err error) {

	caPrivKey, err := ssh.ParsePrivateKey(caPrivKeyBytes)
	if err != nil {
		log.Criticalf("Failed to parse CA private key with error: %v\n", err)
		return
	}
	caPubKey := caPrivKey.PublicKey()
	ca = &caPubKey

	privateRSAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Criticalf("Failed to gen privateKey: %v", err)
		return
	}

	sshPubKey, err := ssh.NewPublicKey(&privateRSAKey.PublicKey)
	if err != nil {
		log.Criticalf("Failed to create ssh public key: %v", err)
		return
	}

	hostCert := &ssh.Certificate{
		Key:             sshPubKey,
		CertType:        ssh.HostCert,
		KeyId:           "server",
		ValidPrincipals: []string{}, // Add hostname to restrict to only a single valid hostname
	}

	err = hostCert.SignCert(rand.Reader, caPrivKey)
	if err != nil {
		log.Criticalf("Failed to sign host cert: %v\n", err)
		return
	}

	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateRSAKey),
		},
	)
	privateHostKey, err := ssh.ParsePrivateKey(pemdata)
	if err != nil {
		log.Criticalf("Failed to parse private key: %v", err)
		return
	}

	cert, err = ssh.NewCertSigner(hostCert, privateHostKey)

	return
}
