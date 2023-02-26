package pkt

import (
	"bytes"
	"log"
	"net"
	"os"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/hwipl/listnd/internal/dev"
)

func testParseCreatePacket() gopacket.Packet {
	// prepare creation of packet
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	pktBuf := gopacket.NewSerializeBuffer()

	// create headers
	ethLayer := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
		DstMAC:       net.HardwareAddr{6, 5, 4, 3, 2, 1},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipLayer := &layers.IPv4{
		SrcIP: net.IP{127, 0, 0, 1},
		DstIP: net.IP{127, 0, 0, 2},
	}

	// serialize to buffer
	err := gopacket.SerializeLayers(pktBuf, opts,
		ethLayer, ipLayer)
	if err != nil {
		log.Fatal(err)
	}

	// create packet from buffer
	pkt := gopacket.NewPacket(pktBuf.Bytes(), layers.LayerTypeEthernet,
		gopacket.Default)
	return pkt
}
func TestSetDebug(t *testing.T) {
	var buf bytes.Buffer
	var want, got string

	// redirect output to buffer
	debugOut = &buf
	defer func() {
		debugOut = os.Stdout
	}()

	// test with debug mode
	SetDebug(true)
	debug("debug test message")
	want = "debug test message\n"
	got = buf.String()
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}

	// test without debug mode
	buf.Reset()
	SetDebug(false)
	debug("debug test message")
	want = ""
	got = buf.String()
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}
}

func TestSetPeers(t *testing.T) {
	var buf bytes.Buffer
	var want, got string

	// test with peer mode
	devices = &dev.DeviceMap{}
	SetPeers(true)
	Parse(testParseCreatePacket())
	devices.Print(&buf)
	want = "=================================================" +
		"=====================\n" +
		"Devices: 1                                       " +
		"(pkts: 1)\n" +
		"=================================================" +
		"=====================\n" +
		"MAC: 01:02:03:04:05:06                           " +
		"(age: -1, pkts: 1)\n" +
		"  MAC Peers:\n" +
		"    MAC: 06:05:04:03:02:01                       " +
		"(age: -1, pkts: 1)\n" +
		"  IP Peers:\n" +
		"    IP: 127.0.0.2                                " +
		"(age: -1, pkts: 1)\n\n"
	got = buf.String()
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}

	// test without peer mode
	buf.Reset()
	devices = &dev.DeviceMap{}
	SetPeers(false)
	Parse(testParseCreatePacket())
	devices.Print(&buf)
	want = "=================================================" +
		"=====================\n" +
		"Devices: 1                                       " +
		"(pkts: 1)\n" +
		"=================================================" +
		"=====================\n" +
		"MAC: 01:02:03:04:05:06                           " +
		"(age: -1, pkts: 1)\n\n"
	got = buf.String()
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}
}

func TestSetDevices(t *testing.T) {
	dm := &dev.DeviceMap{}
	SetDevices(dm)
	if devices != dm {
		t.Errorf("devices = %p, want %p", devices, dm)
	}
}

func TestParse(t *testing.T) {
	var buf bytes.Buffer
	var want, got string

	devices = &dev.DeviceMap{}
	Parse(testParseCreatePacket())
	devices.Print(&buf)
	want = "=================================================" +
		"=====================\n" +
		"Devices: 1                                       " +
		"(pkts: 1)\n" +
		"=================================================" +
		"=====================\n" +
		"MAC: 01:02:03:04:05:06                           " +
		"(age: -1, pkts: 1)\n\n"
	got = buf.String()
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}
}
