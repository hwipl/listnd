package dev

import (
	"log"
	"net"
	"testing"

	"github.com/gopacket/gopacket/layers"
)

func TestAddrInfo(t *testing.T) {
	var a AddrInfo
	var want, got string

	// test empty
	want = "IP: []                                       " +
		"(age: -1, pkts: 0)"
	got = a.String()
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}

	// test with mac
	mac, err := net.ParseMAC("00:00:5e:00:53:01")
	if err != nil {
		log.Fatal(err)
	}
	a.Addr = layers.NewMACEndpoint(mac)
	a.Packets = 13
	want = "MAC: 00:00:5e:00:53:01                       " +
		"(age: -1, pkts: 13)"
	got = a.String()
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}

	// test with ipv4
	a.Addr = layers.NewIPEndpoint(net.IPv4(127, 0, 0, 1))
	a.Packets = 123
	want = "IP: 127.0.0.1                                " +
		"(age: -1, pkts: 123)"
	got = a.String()
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}

	// test with ipv6
	ip := net.ParseIP("2001:db8::68")
	a.Addr = layers.NewIPEndpoint(ip)
	a.Packets = 45
	want = "IP: 2001:db8::68                             " +
		"(age: -1, pkts: 45)"
	got = a.String()
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}
}
