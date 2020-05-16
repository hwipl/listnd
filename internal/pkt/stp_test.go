package pkt

import (
	"bytes"
	"log"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/hwipl/listnd/internal/dev"
)

func testParseSTPCreatePacket() gopacket.Packet {
	// prepare creation of packet
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	pktBuf := gopacket.NewSerializeBuffer()

	// create headers
	ethLayer := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
		DstMAC:       net.HardwareAddr{0x1, 0x80, 0xC2, 0x0, 0x0, 0x0},
		EthernetType: layers.EthernetTypeLLC,
		Length:       38,
	}
	llcLayer := &layers.LLC{
		DSAP:    0x42,
		SSAP:    0x42,
		Control: 0x3,
	}
	stpLayer := gopacket.Payload(make([]byte, 38))

	// serialize to buffer
	err := gopacket.SerializeLayers(pktBuf, opts,
		ethLayer, llcLayer, stpLayer)
	if err != nil {
		log.Fatal(err)
	}

	// create packet from buffer
	pkt := gopacket.NewPacket(pktBuf.Bytes(), layers.LayerTypeEthernet,
		gopacket.Default)
	return pkt
}

func TestParseSTP(t *testing.T) {
	var buf bytes.Buffer
	var want, got string

	// set device table
	devices = &dev.DeviceMap{}

	// create and parse packet
	parseStp(testParseSTPCreatePacket())

	// check output
	devices.Print(&buf)
	want = "=================================================" +
		"=====================\n" +
		"Devices: 1                                       " +
		"(pkts: 0)\n" +
		"=================================================" +
		"=====================\n" +
		"MAC: 01:02:03:04:05:06                           " +
		"(age: -1, pkts: 0)\n" +
		"  Properties:\n" +
		"    Bridge: true                                 " +
		"(age: -1)\n\n"
	got = buf.String()
	if got != want {
		t.Errorf("got = %s; want = %s", got, want)
	}
}
