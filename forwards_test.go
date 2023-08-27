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

type reverseForwardRequest struct {
	BindAddr string
	BindPort uint32
}

type localForwardChannelData struct {
	DestHost   string
	DestPort   uint32
	OriginHost string
	OriginPort uint32
}
*/

func TestEmptyCheckReverseForward(t *testing.T) {
	p := permissions{}
	c := Client{
		privs: p,
	}

	r := reverseForwardRequest{
		BindAddr: "0.0.0.0",
		BindPort: 4444,
	}

	allowed := checkReverseForward(&c, &r)
	if allowed {
		t.Fatalf("Empty permissions should deny all reverse forwards, but was allowed")
	}
}

func TestGeneralAllowCheckReverseForward(t *testing.T) {
	p := permissions{
		allowReverseForward: true,
	}
	c := Client{
		privs: p,
	}

	r := reverseForwardRequest{
		BindAddr: "0.0.0.0",
		BindPort: 4444,
	}

	allowed := checkReverseForward(&c, &r)
	if !allowed {
		t.Fatalf("A general allowReverseForward permission should allow all reverse forwards, but was denied")
	}
}

func TestSpecificAllowCheckReverseForward(t *testing.T) {
	allow := make(map[int]net.IP)
	allow[4444] = net.ParseIP("127.0.0.1")

	p := permissions{
		allowedListen: allow,
	}
	c := Client{
		privs: p,
	}

	r := reverseForwardRequest{
		BindAddr: "127.0.0.1",
		BindPort: 4444,
	}

	allowed := checkReverseForward(&c, &r)
	if !allowed {
		t.Fatalf("A specific allowReverseForward permission should allow a matching reverse forwards, but was denied")
	}
}

func TestWildcardAllowCheckReverseForward(t *testing.T) {
	allow := make(map[int]net.IP)
	allow[4444] = net.ParseIP("0.0.0.0")

	p := permissions{
		allowedListen: allow,
	}
	c := Client{
		privs: p,
	}

	r := reverseForwardRequest{
		BindAddr: "127.0.0.1",
		BindPort: 4444,
	}

	allowed := checkReverseForward(&c, &r)
	if !allowed {
		t.Fatalf("A wildcard allowReverseForward permission should allow all reverse forwards matching the bind port, but was denied")
	}
}

func TestEmptyCheckLocalForward(t *testing.T) {
	p := permissions{}
	c := Client{
		privs: p,
	}

	d := localForwardChannelData{
		DestHost: "127.0.0.1",
		DestPort: 1234,
	}

	allowed := checkLocalForward(&c, &d)
	if allowed {
		t.Fatalf("Empty permissions should deny all local forwards, but was allowed")
	}
}

func TestGeneralAllowCheckLocalForward(t *testing.T) {
	p := permissions{
		allowForward: true,
	}
	c := Client{
		privs: p,
	}

	d := localForwardChannelData{
		DestHost: "127.0.0.1",
		DestPort: 1234,
	}

	allowed := checkLocalForward(&c, &d)
	if !allowed {
		t.Fatalf("A general allowForward permission should allow all local forwards, but was denied")
	}
}

func TestSpecificAllowCheckLocalForward(t *testing.T) {
	allow := make(map[int]net.IP)
	allow[4444] = net.ParseIP("127.0.0.1")

	p := permissions{
		allowedOpen: allow,
	}
	c := Client{
		privs: p,
	}

	d := localForwardChannelData{
		DestHost: "127.0.0.1",
		DestPort: 4444,
	}

	allowed := checkLocalForward(&c, &d)
	if !allowed {
		t.Fatalf("A specific allowForward permission should allow a matching local forwards, but was denied")
	}
}

func TestWildcardAllowCheckLocalForward(t *testing.T) {
	allow := make(map[int]net.IP)
	allow[4444] = net.ParseIP("0.0.0.0")

	p := permissions{
		allowedOpen: allow,
	}
	c := Client{
		privs: p,
	}

	d := localForwardChannelData{
		DestHost: "127.0.0.1",
		DestPort: 4444,
	}

	allowed := checkLocalForward(&c, &d)
	if !allowed {
		t.Fatalf("A wildcard allowForward permission should allow all forwards matching the destination port, but was denied")
	}
}
