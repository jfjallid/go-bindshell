//go:build pubkeyauth

package main

import (
    "fmt"
    _ "embed"
	"golang.org/x/crypto/ssh"
)

//go:embed authorized_keys
var authorizedKeysBytes []byte

func init() {
    features["pubkey"] = createPubkeyCallback
}

func createPubkeyCallback() (func(ssh.ConnMetadata, ssh.PublicKey)(*ssh.Permissions, error), error) {
    authorizedKeysMap, err := parseAuthorizedKeys()
    if err != nil {
        log.Errorln(err)
        return nil, err
    }

    return func (c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
        if m, ok := authorizedKeysMap[string(pubKey.Marshal())]; ok {
            m["pubkey-fp"] = ssh.FingerprintSHA256(pubKey)
    
            return &ssh.Permissions{
                // Record the public key used for authentication.
                Extensions: m,
            }, nil
        }
        log.Infof("Unknown publickey: %s\n", ssh.FingerprintSHA256(pubKey))
        return nil, fmt.Errorf("unknown public key for %q", c.User())
    }, nil
}

func parseAuthorizedKeys() (authorizedKeysMap map[string]map[string]string, err error) {

	// Public key authentication is done by comparing the public key of a
	// received connection with the entries in the authorized_keys file
	// included by go:embed authorized_keys
	//authorizedKeysMap := map[string]bool{}

	authorizedKeysMap = make(map[string]map[string]string)
	for len(authorizedKeysBytes) > 0 {
		pubKey, comment, options, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		if err != nil {
			log.Criticalln(err)
			return nil, err
		}
        log.Debugf("Pubkey had comment: (%s) and options: (%v)\n", comment, options)
		/* NOTE consider using a struct as value for map to add info such as
		   comment from the authorized_keys file. Could be used to store allowed
		   username to connect a public key to a username that owns the key
		   and then validate the username against the struct in the callback.
		*/
        m := make(map[string]string)
        for _, c := range options {
            m[c] = ""
        }

		authorizedKeysMap[string(pubKey.Marshal())] = m
		authorizedKeysBytes = rest
	}
    return
}
