package dev

import (
	"bytes"
	"log"
	"net"
	"testing"

	"github.com/google/gopacket/layers"
)

func TestDeviceMapAdd(t *testing.T) {
	var d DeviceMap
	var want, got *DeviceInfo

	// prepare mac
	m, err := net.ParseMAC("00:00:5e:00:53:01")
	if err != nil {
		log.Fatal(err)
	}
	mac := layers.NewMACEndpoint(m)

	// test
	want = d.Add(mac)
	got = d.Get(mac)
	if got != want {
		t.Errorf("got = %p; want = %p", got, want)
	}
}

func TestDeviceMapGet(t *testing.T) {
	var d DeviceMap
	var want, got *DeviceInfo

	// prepare mac
	m, err := net.ParseMAC("00:00:5e:00:53:01")
	if err != nil {
		log.Fatal(err)
	}
	mac := layers.NewMACEndpoint(m)

	// test empty
	want = nil
	got = d.Get(mac)
	if got != want {
		t.Errorf("got = %p; want = %p", got, want)
	}

	// test filled
	want = d.Add(mac)
	got = d.Get(mac)
	if got != want {
		t.Errorf("got = %p; want = %p", got, want)
	}
}

func TestDeviceMapReset(t *testing.T) {
	var d DeviceMap
	var want, got int

	// prepare mac
	m, err := net.ParseMAC("00:00:5e:00:53:01")
	if err != nil {
		log.Fatal(err)
	}
	mac := layers.NewMACEndpoint(m)

	// test empty
	d.Reset()
	want = 0
	got = len(d.m)
	if got != want {
		t.Errorf("got = %d; want = %d", got, want)
	}

	// test filled
	d.Add(mac)
	d.Reset()
	want = 0
	got = len(d.m)
	if got != want {
		t.Errorf("got = %d; want = %d", got, want)
	}
}

func TestDeviceMapPrint(t *testing.T) {
	var d DeviceMap
	var buf bytes.Buffer
	var want, got string

	// test empty
	d.Print(&buf)
	want = "=================================================" +
		"=====================\n" +
		"Devices: 0                                       " +
		"(pkts: 0)\n" +
		"=================================================" +
		"=====================\n"
	got = buf.String()
	if got != want {
		t.Errorf("got = %s; want = %s", got, want)
	}
	buf.Reset()

	// test filled
	// prepare mac
	m, err := net.ParseMAC("00:00:5e:00:53:01")
	if err != nil {
		log.Fatal(err)
	}
	mac := layers.NewMACEndpoint(m)

	// add and test
	d.Add(mac)
	d.Print(&buf)
	want = "=================================================" +
		"=====================\n" +
		"Devices: 1                                       " +
		"(pkts: 0)\n" +
		"=================================================" +
		"=====================\n" +
		"MAC: 00:00:5e:00:53:01                           " +
		"(age: -1, pkts: 0)\n\n"
	got = buf.String()
	if got != want {
		t.Errorf("got = %s; want = %s", got, want)
	}
}
