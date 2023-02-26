package dev

import (
	"testing"

	"github.com/gopacket/gopacket/layers"
)

func TestPrefixInfo(t *testing.T) {
	var p PrefixInfo
	var want, got string

	// fill prefix info
	p.Prefix = layers.ICMPv6Option{
		Type: layers.ICMPv6OptPrefixInfo,
		Data: []byte{
			// Example from gopacket/layers/icmp6msg_test.go:
			// prefix info option (3), length 32 (4):
			// 2001:db8:0:1::/64, Flags [onlink, auto], valid time
			// 2592000s, pref. time 604800s
			//   0x0000:  40c0 0027 8d00 0009 3a80 0000 0000 2001
			//   0x0010:  0db8 0000 0001 0000 0000 0000 0000
			0x40, 0xc0, 0x00, 0x27, 0x8d, 0x00, 0x00, 0x09, 0x3a,
			0x80, 0x00, 0x00, 0x00, 0x00, 0x20, 0x01, 0x0d, 0xb8,
			0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00,
		},
	}

	// test
	want = "Prefix: 2001:db8:0:1::/64                  (age: -1)"
	got = p.String()
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}
}
