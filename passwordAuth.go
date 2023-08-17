//go:build passauth

package main

import (
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/ssh"
)

//go:embed users.json
var usersBytes []byte

func init() {
	features["password"] = createPasswordCallback
}

func createPasswordCallback() (func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error), error) {
	credMap, err := parseUserCreds()
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	return func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
		if pwHash, ok := credMap[c.User()]; ok {
			psk := sha256.Sum256(pass)
			if subtle.ConstantTimeCompare(psk[:], pwHash) == 1 {
				// Assume full permissions. Could block certain functionality based on username
				perm := &ssh.Permissions{
					CriticalOptions: make(map[string]string),
					Extensions:      make(map[string]string),
				}
				return perm, nil
			}
		}

		return nil, fmt.Errorf("username or password rejected for provided user %q", c.User())
	}, nil
}

type UserPass struct {
	Username string
	Password string
}

/*
Expects an array of json objects with credentials:
[

	{"Username": "user1", "Password": "summer2020"},
	{"Username": "user2", "Password": "secretpass"},
	...

]
*/
func parseUserCreds() (creds map[string][]byte, err error) {
	passlist := []UserPass{}

	if len(usersBytes) == 0 {
		err = fmt.Errorf("No valid user credentials found")
		log.Errorln(err)
		return
	}
	err = json.Unmarshal(usersBytes, &passlist)
	if err != nil {
		log.Errorln(err)
		return
	}

	creds = make(map[string][]byte)

	// Hash passwords
	for i := range passlist {
		hash := sha256.Sum256([]byte(passlist[i].Password))
		creds[passlist[i].Username] = hash[:]
	}
	return
}
