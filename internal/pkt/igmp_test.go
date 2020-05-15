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

func testParseIGMPv1or2Type(msgType layers.IGMPType) {
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
		Protocol: layers.IPProtocolIGMP,
	}
	// layer IGMPv1or2 does not have a SerializeTo() method,
	// build dummy payload
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |      Type     | Max Resp Time |           Checksum            |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                         Group Address                         |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	igmpLayer := gopacket.Payload([]byte{
		byte(msgType), 0, 0, 0,
		240, 0, 0, 1,
	})

	// serialize to buffer
	err := gopacket.SerializeLayers(pktBuf, opts,
		ethLayer, ipLayer, igmpLayer)
	if err != nil {
		log.Fatal(err)
	}

	// create packet from buffer
	pkt := gopacket.NewPacket(pktBuf.Bytes(), layers.LayerTypeEthernet,
		gopacket.Default)

	// parse packet
	parseIgmp(pkt)
}

func TestParseIGMPv1or2(t *testing.T) {
	var buf bytes.Buffer
	var want, got string

	// set device table
	devices = &dev.DeviceMap{}

	// test packet parsing
	ops := []layers.IGMPType{
		layers.IGMPMembershipQuery,
		layers.IGMPMembershipReportV1,
		layers.IGMPMembershipReportV2,
		// test layers.IGMPLeaveGroup later
	}
	for _, op := range ops {
		testParseIGMPv1or2Type(op)
	}

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
		"  Unicast Addresses:\n" +
		"    IP: 127.0.0.1                                " +
		"(age: -1, pkts: 0)\n" +
		"  Multicast Addresses:\n" +
		"    IP: 240.0.0.1                                " +
		"(age: -1, pkts: 0)\n\n"
	got = buf.String()
	if got != want {
		t.Errorf("got = %s; want = %s", got, want)
	}
	buf.Reset()

	// test leave message
	testParseIGMPv1or2Type(layers.IGMPLeaveGroup)
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
		"  Unicast Addresses:\n" +
		"    IP: 127.0.0.1                                " +
		"(age: -1, pkts: 0)\n\n"
	got = buf.String()
	if got != want {
		t.Errorf("got = %s; want = %s", got, want)
	}
}

func testParseIGMPv3MembershipQuery() {
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
		Protocol: layers.IPProtocolIGMP,
	}
	// layer IGMP does not have a SerializeTo() method,
	// build dummy payload
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |  Type = 0x11  | Max Resp Code |           Checksum            |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                         Group Address                         |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | Resv  |S| QRV |     QQIC      |     Number of Sources (N)     |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                       Source Address [1]                      |
	// +-                                                             -+
	// |                       Source Address [2]                      |
	// +-                              .                              -+
	// .                               .                               .
	// .                               .                               .
	// +-                                                             -+
	// |                       Source Address [N]                      |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	igmpLayer := gopacket.Payload([]byte{
		0x11, 0, 0, 0,
		240, 0, 0, 1,
		0, 0, 0, 0,
	})

	// serialize to buffer
	err := gopacket.SerializeLayers(pktBuf, opts,
		ethLayer, ipLayer, igmpLayer)
	if err != nil {
		log.Fatal(err)
	}

	// create packet from buffer
	pkt := gopacket.NewPacket(pktBuf.Bytes(), layers.LayerTypeEthernet,
		gopacket.Default)

	// parse packet
	parseIgmp(pkt)
}

func testParseIGMPv3MembershipReport(recordType layers.IGMPv3GroupRecordType) {
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
		Protocol: layers.IPProtocolIGMP,
	}
	// layer IGMP does not have a SerializeTo() method,
	// build dummy payload
	// Report Message:
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |  Type = 0x22  |    Reserved   |           Checksum            |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |           Reserved            |  Number of Group Records (M)  |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                                                               |
	// .                                                               .
	// .                        Group Record [1]                       .
	// .                                                               .
	// |                                                               |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// [...]
	// Group Record:
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |  Record Type  |  Aux Data Len |     Number of Sources (N)     |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                       Multicast Address                       |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                       Source Address [1]                      |
	// +-                                                             -+
	// |                       Source Address [2]                      |
	// +-                                                             -+
	// .                               .                               .
	// .                               .                               .
	// .                               .                               .
	// +-                                                             -+
	// |                       Source Address [N]                      |
	//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                                                               |
	// .                                                               .
	// .                         Auxiliary Data                        .
	// .                                                               .
	// |                                                               |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	igmpLayer := gopacket.Payload([]byte{
		0x22, 0, 0, 0,
		0, 0, 0, 1,
		byte(recordType), 0, 0, 0,
		240, 0, 0, 1,
	})

	// serialize to buffer
	err := gopacket.SerializeLayers(pktBuf, opts,
		ethLayer, ipLayer, igmpLayer)
	if err != nil {
		log.Fatal(err)
	}

	// create packet from buffer
	pkt := gopacket.NewPacket(pktBuf.Bytes(), layers.LayerTypeEthernet,
		gopacket.Default)

	// parse packet
	parseIgmp(pkt)
}
func TestParseIGMPv3(t *testing.T) {
	var buf bytes.Buffer
	var want, got string

	// set device table
	devices = &dev.DeviceMap{}

	// test membership query and membership report with exclude filter
	testParseIGMPv3MembershipQuery()
	recordTypes := []layers.IGMPv3GroupRecordType{
		layers.IGMPToEx,
		layers.IGMPIsEx,
	}
	for _, record := range recordTypes {
		testParseIGMPv3MembershipReport(record)
	}

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
		"  Unicast Addresses:\n" +
		"    IP: 127.0.0.1                                " +
		"(age: -1, pkts: 0)\n" +
		"  Multicast Addresses:\n" +
		"    IP: 240.0.0.1                                " +
		"(age: -1, pkts: 0)\n\n"
	got = buf.String()
	if got != want {
		t.Errorf("got = %s; want = %s", got, want)
	}
	buf.Reset()

	// test membership report with include filter
	recordTypes = []layers.IGMPv3GroupRecordType{
		layers.IGMPToIn,
		layers.IGMPIsIn,
	}
	for _, record := range recordTypes {
		testParseIGMPv3MembershipReport(record)
	}

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
		"  Unicast Addresses:\n" +
		"    IP: 127.0.0.1                                " +
		"(age: -1, pkts: 0)\n\n"
	got = buf.String()
	if got != want {
		t.Errorf("got = %s; want = %s", got, want)
	}
}
