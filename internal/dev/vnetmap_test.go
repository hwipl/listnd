package dev

import (
	"bytes"
	"testing"
)

func TestVNetMapAdd(t *testing.T) {
	var v VNetMap
	var want, got *VNetInfo

	want = v.Add(42)
	got = v.Get(42)
	if got != want {
		t.Errorf("got = %p; want %p", got, want)
	}
}

func TestVNetMapGet(t *testing.T) {
	var v VNetMap
	var want, got *VNetInfo

	// test empty
	want = nil
	got = v.Get(42)
	if got != want {
		t.Errorf("got = %p; want %p", got, want)
	}

	// test filled
	want = v.Add(42)
	got = v.Get(42)
	if got != want {
		t.Errorf("got = %p; want %p", got, want)
	}
}

func TestVNetMapLen(t *testing.T) {
	var v VNetMap
	var want, got int

	// test empty
	want = 0
	got = v.Len()
	if got != want {
		t.Errorf("got = %d; want %d", got, want)
	}

	// test filled
	v.Add(42)
	want = 1
	got = v.Len()
	if got != want {
		t.Errorf("got = %d; want %d", got, want)
	}
}

func TestVNetMapPrint(t *testing.T) {
	var v VNetMap
	var buf bytes.Buffer
	var want, got string

	// test empty
	v.Print(&buf)
	want = ""
	got = buf.String()
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}
	buf.Reset()

	// test filled
	vnet := v.Add(32)
	vnet.Type = "TestVNet"
	vnet.ID = 32
	vnet.Packets = 128
	v.Print(&buf)
	want = "    TestVNet: 32                                 " +
		"(age: -1, pkts: 128)\n"
	got = buf.String()
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}
}
