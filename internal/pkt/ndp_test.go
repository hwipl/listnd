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

func testParseNDPCreatePacket(
	typeCode layers.ICMPv6TypeCode,
	ndpLayer gopacket.SerializableLayer,
) gopacket.Packet {
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
		EthernetType: layers.EthernetTypeIPv6,
	}
	ipLayer := &layers.IPv6{
		SrcIP:      net.ParseIP("::1"),
		DstIP:      net.ParseIP("::2"),
		NextHeader: layers.IPProtocolICMPv6,
	}
	icmpLayer := &layers.ICMPv6{
		TypeCode: typeCode << 8, // ICMPv6TypeCodes are >> 8, reverse
	}
	icmpLayer.SetNetworkLayerForChecksum(ipLayer)

	// serialize to buffer
	err := gopacket.SerializeLayers(pktBuf, opts,
		ethLayer, ipLayer, icmpLayer, ndpLayer)
	if err != nil {
		log.Fatal(err)
	}

	// create packet from buffer
	pkt := gopacket.NewPacket(pktBuf.Bytes(), layers.LayerTypeEthernet,
		gopacket.Default)
	return pkt
}

func TestParseNDPNeighborSolicitation(t *testing.T) {
	var buf bytes.Buffer
	var want, got string

	// set device table
	devices = &dev.DeviceMap{}

	// create packet
	ndpLayer := &layers.ICMPv6NeighborSolicitation{
		TargetAddress: net.ParseIP("fe80::1"),
	}
	pkt := testParseNDPCreatePacket(layers.ICMPv6TypeNeighborSolicitation,
		ndpLayer)

	// parse packet
	parseNdp(pkt)

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
		"  Unicast Addresses:\n" +
		"    IP: ::1                                      " +
		"(age: -1, pkts: 0)\n\n"
	got = buf.String()
	if got != want {
		t.Errorf("got = %s; want = %s", got, want)
	}
}

func TestParseNDPNeighborAdvertisement(t *testing.T) {
	var buf bytes.Buffer
	var want, got string

	// set device table
	devices = &dev.DeviceMap{}

	// create packet
	ndpLayer := &layers.ICMPv6NeighborAdvertisement{
		TargetAddress: net.ParseIP("fe80::1"),
	}
	pkt := testParseNDPCreatePacket(layers.ICMPv6TypeNeighborAdvertisement,
		ndpLayer)

	// parse packet
	parseNdp(pkt)

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
		"  Unicast Addresses:\n" +
		"    IP: fe80::1                                  " +
		"(age: -1, pkts: 0)\n\n"
	got = buf.String()
	if got != want {
		t.Errorf("got = %s; want = %s", got, want)
	}
}

func TestParseNDPRouterSolicitation(t *testing.T) {
	var buf bytes.Buffer
	var want, got string

	// set device table
	devices = &dev.DeviceMap{}

	// create packet
	ndpLayer := &layers.ICMPv6RouterSolicitation{}
	pkt := testParseNDPCreatePacket(layers.ICMPv6TypeRouterSolicitation,
		ndpLayer)

	// parse packet
	parseNdp(pkt)

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
		"  Unicast Addresses:\n" +
		"    IP: ::1                                      " +
		"(age: -1, pkts: 0)\n\n"
	got = buf.String()
	if got != want {
		t.Errorf("got = %s; want = %s", got, want)
	}
}

func TestParseNDPRouterAdvertisement(t *testing.T) {
	var buf bytes.Buffer
	var want, got string

	// set device table
	devices = &dev.DeviceMap{}

	// create packet
	prefixInfo := [30]byte{}
	prefixInfo[0] = 16
	copy(prefixInfo[14:], net.ParseIP("2001::"))
	opts := layers.ICMPv6Options{
		{
			Type: layers.ICMPv6OptPrefixInfo,
			Data: prefixInfo[:],
		},
	}
	ndpLayer := &layers.ICMPv6RouterAdvertisement{
		Options: opts,
	}
	pkt := testParseNDPCreatePacket(layers.ICMPv6TypeRouterAdvertisement,
		ndpLayer)

	// parse packet
	parseNdp(pkt)

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
		"    Router: true                                 " +
		"(age: -1)\n" +
		"      Prefix: 2001::/16                          " +
		"(age: -1)\n" +
		"  Unicast Addresses:\n" +
		"    IP: ::1                                      " +
		"(age: -1, pkts: 0)\n\n"
	got = buf.String()
	if got != want {
		t.Errorf("got = %s; want = %s", got, want)
	}
}
