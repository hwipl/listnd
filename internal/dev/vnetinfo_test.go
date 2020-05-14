package dev

import "testing"

func TestVNetInfo(t *testing.T) {
	var v VNetInfo
	var want, got string

	// test default
	want = ": 0                                            " +
		"(age: -1, pkts: 0)"
	got = v.String()
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}

	// test filled
	v.Type = "TestVNet"
	v.ID = 32
	v.Packets = 128
	want = "TestVNet: 32                                   " +
		"(age: -1, pkts: 128)"
	got = v.String()
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}
}
