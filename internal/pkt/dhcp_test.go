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

func testParseDHCPv4Operation(op layers.DHCPOp) {
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
		SrcIP:    net.IP{127, 0, 0, 1},
		DstIP:    net.IP{127, 0, 0, 2},
		Protocol: layers.IPProtocolUDP,
	}
	udpLayer := &layers.UDP{
		SrcPort: 67,
		DstPort: 68,
	}
	udpLayer.SetNetworkLayerForChecksum(ipLayer)
	dhcpLayer := &layers.DHCPv4{
		Operation: op,
	}

	// serialize to buffer
	err := gopacket.SerializeLayers(pktBuf, opts,
		ethLayer, ipLayer, udpLayer, dhcpLayer)
	if err != nil {
		log.Fatal(err)
	}

	// create packet from buffer
	pkt := gopacket.NewPacket(pktBuf.Bytes(), layers.LayerTypeEthernet,
		gopacket.Default)

	// parse packet
	parseDhcp(pkt)
}

func TestParseDHCPv4(t *testing.T) {
	var buf bytes.Buffer
	var want, got string

	// set device table
	devices = &dev.DeviceMap{}

	// test packet parsing
	ops := []layers.DHCPOp{
		layers.DHCPOpRequest,
		layers.DHCPOpReply,
	}
	for _, op := range ops {
		testParseDHCPv4Operation(op)
	}

	// check final output
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
		"    DHCP Server: true                            " +
		"(age: -1)\n\n"
	got = buf.String()
	if got != want {
		t.Errorf("got = %s; want = %s", got, want)
	}
}

func testParseDHCPv6MsgType(msgType layers.DHCPv6MsgType) {
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
		NextHeader: layers.IPProtocolUDP,
	}
	udpLayer := &layers.UDP{
		SrcPort: 547,
		DstPort: 546,
	}
	udpLayer.SetNetworkLayerForChecksum(ipLayer)
	dhcpLayer := &layers.DHCPv6{
		MsgType: msgType,
	}

	// serialize to buffer
	err := gopacket.SerializeLayers(pktBuf, opts,
		ethLayer, ipLayer, udpLayer, dhcpLayer)
	if err != nil {
		log.Fatal(err)
	}

	// create packet from buffer
	pkt := gopacket.NewPacket(pktBuf.Bytes(), layers.LayerTypeEthernet,
		gopacket.Default)

	// parse packet
	parseDhcp(pkt)
}

func TestParseDHCPv6(t *testing.T) {
	var buf bytes.Buffer
	var want, got string

	// set device table
	devices = &dev.DeviceMap{}

	// test packet parsing
	ops := []layers.DHCPv6MsgType{
		layers.DHCPv6MsgTypeSolicit,
		layers.DHCPv6MsgTypeAdverstise,
		layers.DHCPv6MsgTypeRequest,
		layers.DHCPv6MsgTypeConfirm,
		layers.DHCPv6MsgTypeRenew,
		layers.DHCPv6MsgTypeRebind,
		layers.DHCPv6MsgTypeReply,
		layers.DHCPv6MsgTypeRelease,
		layers.DHCPv6MsgTypeDecline,
		layers.DHCPv6MsgTypeReconfigure,
		layers.DHCPv6MsgTypeInformationRequest,
		layers.DHCPv6MsgTypeRelayForward,
		layers.DHCPv6MsgTypeRelayReply,
	}
	for _, op := range ops {
		testParseDHCPv6MsgType(op)
	}

	// check final output
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
		"    DHCP Server: true                            " +
		"(age: -1)\n" +
		"  Unicast Addresses:\n" +
		"    IP: ::1                                      " +
		"(age: -1, pkts: 0)\n\n"
	got = buf.String()
	if got != want {
		t.Errorf("got = %s; want = %s", got, want)
	}
}
