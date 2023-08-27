package main

import (
	"net"
	"testing"
)

/*
type permissions struct {
	pty                 bool
	allowForward        bool
	allowReverseForward bool
	allowedOpen         map[int]net.IP
	allowedListen       map[int]net.IP
	restrict            bool
}
*/

func emptyPermissions() permissions {
	return permissions{
		allowedOpen:   make(map[int]net.IP),
		allowedListen: make(map[int]net.IP),
	}
}

// Parse certificate permissions
func TestParseCertPermissionsPTY(t *testing.T) {
	c := Client{
		privs: emptyPermissions(),
	}

	exts := make(map[string]string)
	exts["permit-pty"] = ""

	c.parsePermissions(exts, nil)

	if !c.privs.pty {
		t.Fatal("permit-pty extension should enable pty support but it did not.")
	}
}

func TestParseCertPermissionsGeneralAllow(t *testing.T) {
	c := Client{
		privs: emptyPermissions(),
	}

	exts := make(map[string]string)
	exts["permit-port-forwarding"] = ""

	c.parsePermissions(exts, nil)

	if !c.privs.allowForward || !c.privs.allowReverseForward {
		t.Fatalf("permit-port-forwarding should allow port forwards in both directions but failed with allowForward: %v, allowReverseForward: %v\n", c.privs.allowForward, c.privs.allowReverseForward)
	}
}

func TestParseCertPermissionsOpen(t *testing.T) {
	c := Client{
		privs: emptyPermissions(),
	}

	exts := make(map[string]string)
	exts["permitopen1"] = "127.0.0.1:4444"
	exts["permitopen2"] = "0.0.0.0:1234"

	c.parsePermissions(exts, nil)

	val, ok := c.privs.allowedOpen[4444]
	if !ok {
		t.Fatal("permitopen1:127.0.0.1:4444 should create the allowedOpen map key 4444, but it did not")
	}
	if !val.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("permitopen1:127.0.0.1:4444 should create the allowedOpen map key 4444 with the value 127.0.0.1, but the value was: %s\n", val)
	}

	val, ok = c.privs.allowedOpen[1234]
	if !ok {
		t.Fatal("permitopen2:0.0.0.0:1234 should create the allowedOpen map key 1234, but it did not")
	}
	if !val.Equal(net.ParseIP("0.0.0.0")) {
		t.Fatalf("permitopen2:0.0.0.0:1234 should create the allowedOpen map key 1234 with the value 0.0.0.0, but the value was: %s\n", val)
	}

}

func TestParseCertPermissionsListen(t *testing.T) {
	c := Client{
		privs: emptyPermissions(),
	}

	exts := make(map[string]string)
	exts["permitlisten1"] = "127.0.0.1:4444"
	exts["permitlisten2"] = "0.0.0.0:1234"

	c.parsePermissions(exts, nil)

	val, ok := c.privs.allowedListen[4444]
	if !ok {
		t.Fatal("permitlisten1:127.0.0.1:4444 should create the allowedListen map key 4444, but it did not")
	}
	if !val.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("permitlisten1:127.0.0.1:4444 should create the allowedListen map key 4444 with the value 127.0.0.1, but the value was: %s\n", val)
	}

	val, ok = c.privs.allowedListen[1234]
	if !ok {
		t.Fatal("permitlisten2:0.0.0.0:1234 should create the allowedListen map key 1234, but it did not")
	}
	if !val.Equal(net.ParseIP("0.0.0.0")) {
		t.Fatalf("permitlisten2:0.0.0.0:1234 should create the allowedListen map key 1234 with the value 0.0.0.0, but the value was: %s\n", val)
	}
}

func TestParseCertPermissionsListenAny(t *testing.T) {
	c := Client{
		privs: emptyPermissions(),
	}

	exts := make(map[string]string)
	exts["permitlisten1"] = "any"

	c.parsePermissions(exts, nil)

	if !c.privs.allowReverseForward {
		t.Fatal("permitlisten1: any should allow all reverse port forwards but did not")
	}
}

func TestParseCertPermissionsOpenAny(t *testing.T) {
	c := Client{
		privs: emptyPermissions(),
	}

	exts := make(map[string]string)
	exts["permitopen1"] = "any"

	c.parsePermissions(exts, nil)

	if !c.privs.allowForward {
		t.Fatal("permitopen1: any should allow all local port forwards but did not")
	}
}

func TestParseCertPermissionsListenNone(t *testing.T) {
	c := Client{
		privs: emptyPermissions(),
	}

	exts := make(map[string]string)
	exts["permitlisten1"] = "none"
	exts["permitlisten2"] = "127.0.0.1:1234"

	c.parsePermissions(exts, nil)

	if c.privs.allowReverseForward {
		t.Fatal("permitlisten1: none should disallow all reverse port forwards, but general reverse forwarding was enabled")
	}

	if len(c.privs.allowedListen) > 0 {
		t.Fatalf("permitlisten1: none should disallow all reverse port forwards regardless of other permitlisten statements, but it did not. A specific allowListen rule was found: %v\n", c.privs.allowedListen)
	}
}

func TestParseCertPermissionsOpenNone(t *testing.T) {
	c := Client{
		privs: emptyPermissions(),
	}

	exts := make(map[string]string)
	exts["permitopen1"] = "none"
	exts["permitopen2"] = "127.0.0.1:1234"

	c.parsePermissions(exts, nil)

	if c.privs.allowForward {
		t.Fatal("permitopen1: none should disallow all port forwards, but general port forwarding was enabled")
	}

	if len(c.privs.allowedOpen) > 0 {
		t.Fatalf("permitopen1: none should disallow all port forwards regardless of other permitopen statements, but it did not. A specific allowOpen rule was found: %v\n", c.privs.allowedOpen)
	}
}

// Parse pubkey permissions
func TestParsePubkeyPermissionsPTY(t *testing.T) {
	c := Client{
		privs: emptyPermissions(),
	}

	opts := []string{""}
	c.parsePubkeyOptions(opts)

	if !c.privs.pty {
		t.Fatal("Without restrict and with no explicit no-pty option, pty should be allowed but it was not")
	}

	opts = []string{"no-pty"}
	c.privs = emptyPermissions()
	c.parsePubkeyOptions(opts)

	if c.privs.pty {
		t.Fatal("no-pty option should disable pty support but it did not.")
	}

	opts = []string{"restrict", "pty"}
	c.privs = emptyPermissions()
	c.parsePubkeyOptions(opts)

	if !c.privs.pty {
		t.Fatal("restrict + pty options should allow pty support but it did not.")
	}
}

func TestParsePubkeyPermissionsGeneralAllow(t *testing.T) {
	c := Client{
		privs: emptyPermissions(),
	}

	opts := []string{""}
	c.parsePubkeyOptions(opts)

	if !c.privs.allowForward || !c.privs.allowReverseForward {
		t.Fatalf("without restrict or no-port-forwarding keywords, general port forwards in both directions should be allowed but failed with allowForward: %v, allowReverseForward: %v\n", c.privs.allowForward, c.privs.allowReverseForward)
	}

	opts = []string{"restrict"}
	c.privs = emptyPermissions()
	c.parsePubkeyOptions(opts)

	if c.privs.allowForward || c.privs.allowReverseForward {
		t.Fatalf("With restrict keyword, general port forwards in both directions should be disallowed but failed with allowForward: %v, allowReverseForward: %v\n", c.privs.allowForward, c.privs.allowReverseForward)
	}

	opts = []string{"no-port-forwarding"}
	c.privs = emptyPermissions()
	c.parsePubkeyOptions(opts)

	if c.privs.allowForward || c.privs.allowReverseForward || (len(c.privs.allowedListen) > 0) || (len(c.privs.allowedOpen) > 0) {
		t.Fatalf("With no-port-forwarding keyword, all port forwards in both directions should be disallowed but failed with allowForward: %v, allowReverseForward: %v, allowedOpen: %v, allowedListen: %v\n", c.privs.allowForward, c.privs.allowReverseForward, c.privs.allowedOpen, c.privs.allowedListen)
	}
}

func TestParsePubkeyPermissionsOpen(t *testing.T) {
	c := Client{
		privs: emptyPermissions(),
	}

	opts := []string{"permitopen=127.0.0.1:4444", "permitopen=0.0.0.0:1234"}
	c.parsePubkeyOptions(opts)

	val, ok := c.privs.allowedOpen[4444]
	if !ok {
		t.Fatal("permitopen=127.0.0.1:4444 should create the allowedOpen map key 4444, but it did not")
	}
	if !val.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("permitopen=127.0.0.1:4444 should create the allowedOpen map key 4444 with the value 127.0.0.1, but the value was: %s\n", val)
	}

	val, ok = c.privs.allowedOpen[1234]
	if !ok {
		t.Fatal("permitopen=0.0.0.0:1234 should create the allowedOpen map key 1234, but it did not")
	}
	if !val.Equal(net.ParseIP("0.0.0.0")) {
		t.Fatalf("permitopen=0.0.0.0:1234 should create the allowedOpen map key 1234 with the value 0.0.0.0, but the value was: %s\n", val)
	}

	opts = []string{"restrict", "permitopen=127.0.0.1:4444"}
	c.privs = emptyPermissions()
	c.parsePubkeyOptions(opts)

	val, ok = c.privs.allowedOpen[4444]
	if !ok {
		t.Fatal("permitopen=127.0.0.1:4444 with the restrict keyword should create the allowedOpen map key 4444, but it did not")
	}
	if !val.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("permitopen=127.0.0.1:4444 with the restrict keyword should create the allowedOpen map key 4444 with the value 127.0.0.1, but the value was: %s\n", val)
	}
}

func TestParsePubkeyPermissionsListen(t *testing.T) {
	c := Client{
		privs: emptyPermissions(),
	}

	opts := []string{"permitlisten=127.0.0.1:4444", "permitlisten=0.0.0.0:1234"}
	c.parsePubkeyOptions(opts)

	val, ok := c.privs.allowedListen[4444]
	if !ok {
		t.Fatal("permitlisten=127.0.0.1:4444 should create the allowedListen map key 4444, but it did not")
	}
	if !val.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("permitlisten=127.0.0.1:4444 should create the allowedListen map key 4444 with the value 127.0.0.1, but the value was: %s\n", val)
	}

	val, ok = c.privs.allowedListen[1234]
	if !ok {
		t.Fatal("permitlisten=0.0.0.0:1234 should create the allowedListen map key 1234, but it did not")
	}
	if !val.Equal(net.ParseIP("0.0.0.0")) {
		t.Fatalf("permitlisten=0.0.0.0:1234 should create the allowedListen map key 1234 with the value 0.0.0.0, but the value was: %s\n", val)
	}

	opts = []string{"restrict", "permitlisten=127.0.0.1:4444"}
	c.privs = emptyPermissions()
	c.parsePubkeyOptions(opts)

	val, ok = c.privs.allowedListen[4444]
	if !ok {
		t.Fatal("permitlisten=127.0.0.1:4444 with the restrict keyword should create the allowedListen map key 4444, but it did not")
	}
	if !val.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("permitlisten=127.0.0.1:4444 with the restrict keyword should create the allowedListen map key 4444 with the value 127.0.0.1, but the value was: %s\n", val)
	}
}

func TestParsePubkeyPermissionsListenAny(t *testing.T) {
	c := Client{
		privs: emptyPermissions(),
	}

	opts := []string{"permitlisten=any"}
	c.parsePubkeyOptions(opts)

	if !c.privs.allowReverseForward {
		t.Fatal("permitlisten=any should allow all reverse port forwards but did not")
	}
}

func TestParsePubkeyPermissionsOpenAny(t *testing.T) {
	c := Client{
		privs: emptyPermissions(),
	}

	opts := []string{"permitopen=any"}
	c.parsePubkeyOptions(opts)

	if !c.privs.allowForward {
		t.Fatal("permitopen=any should allow all local port forwards but did not")
	}
}

func TestParsePubkeyPermissionsListenNone(t *testing.T) {
	c := Client{
		privs: emptyPermissions(),
	}

	opts := []string{"permitlisten=none", "permitlisten=127.0.0.1:1234"}
	c.parsePubkeyOptions(opts)

	if c.privs.allowReverseForward {
		t.Fatal("permitlisten=none should disallow all reverse port forwards, but general reverse forwarding was enabled")
	}

	if len(c.privs.allowedListen) > 0 {
		t.Fatalf("permitlisten=none should disallow all reverse port forwards regardless of other permitlisten statements, but it did not. A specific allowListen rule was found: %v\n", c.privs.allowedListen)
	}
}

func TestParsePubkeyPermissionsOpenNone(t *testing.T) {
	c := Client{
		privs: emptyPermissions(),
	}

	opts := []string{"permitopen=none", "permitopen=127.0.0.1:1234"}
	c.parsePubkeyOptions(opts)

	if c.privs.allowForward {
		t.Fatal("permitopen=none should disallow all port forwards, but general port forwarding was enabled")
	}

	if len(c.privs.allowedOpen) > 0 {
		t.Fatalf("permitopen=none should disallow all port forwards regardless of other permitopen statements, but it did not. A specific allowOpen rule was found: %v\n", c.privs.allowedOpen)
	}
}
