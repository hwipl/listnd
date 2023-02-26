package pkt

import (
	"bytes"
	"log"
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/hwipl/listnd/internal/dev"
)

func testParseMLDv1TypeCode(typeCode layers.ICMPv6TypeCode) {
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
	// build dummy payload for MLDv1 messages
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |     Type      |     Code      |          Checksum             |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |     Maximum Response Delay    |          Reserved             |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                                                               |
	// +                                                               +
	// |                                                               |
	// +                       Multicast Address                       +
	// |                                                               |
	// +                                                               +
	// |                                                               |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// first 4 bytes are handled by icmp layer
	mldLayer := gopacket.Payload([]byte{
		0, 0, 0, 0,
		255, 2, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 1,
	})

	// serialize to buffer
	err := gopacket.SerializeLayers(pktBuf, opts,
		ethLayer, ipLayer, icmpLayer, mldLayer)
	if err != nil {
		log.Fatal(err)
	}

	// create packet from buffer
	pkt := gopacket.NewPacket(pktBuf.Bytes(), layers.LayerTypeEthernet,
		gopacket.Default)

	// parse packet
	parseMld(pkt)
}

func TestParseMLDv1(t *testing.T) {
	var buf bytes.Buffer
	var want, got string

	// set device table
	devices = &dev.DeviceMap{}

	// test query and report parsing
	typeCodes := []layers.ICMPv6TypeCode{
		layers.ICMPv6TypeMLDv1MulticastListenerQueryMessage,
		layers.ICMPv6TypeMLDv1MulticastListenerReportMessage,
	}
	for _, tc := range typeCodes {
		testParseMLDv1TypeCode(tc)
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
		"    IP: ::1                                      " +
		"(age: -1, pkts: 0)\n" +
		"  Multicast Addresses:\n" +
		"    IP: ff02::1                                  " +
		"(age: -1, pkts: 0)\n\n"
	got = buf.String()
	if got != want {
		t.Errorf("got = %s; want = %s", got, want)
	}
	buf.Reset()

	// test done parsing
	const tc = layers.ICMPv6TypeMLDv1MulticastListenerDoneMessage
	testParseMLDv1TypeCode(tc)

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
		"    IP: ::1                                      " +
		"(age: -1, pkts: 0)\n\n"
	got = buf.String()
	if got != want {
		t.Errorf("got = %s; want = %s", got, want)
	}
}

func testParseMLDv2Query() {
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
	const typeCode = layers.ICMPv6TypeMLDv1MulticastListenerQueryMessage
	icmpLayer := &layers.ICMPv6{
		TypeCode: typeCode << 8, // ICMPv6TypeCodes are >> 8, reverse
	}
	icmpLayer.SetNetworkLayerForChecksum(ipLayer)
	mldLayer := &layers.MLDv2MulticastListenerQueryMessage{
		MulticastAddress: net.ParseIP("ff02::1"),
	}

	// serialize to buffer
	err := gopacket.SerializeLayers(pktBuf, opts,
		ethLayer, ipLayer, icmpLayer, mldLayer)
	if err != nil {
		log.Fatal(err)
	}

	// create packet from buffer
	pkt := gopacket.NewPacket(pktBuf.Bytes(), layers.LayerTypeEthernet,
		gopacket.Default)

	// parse packet
	parseMld(pkt)
}

func testParseMLDv2Report(recordType layers.MLDv2MulticastAddressRecordType) {
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
	const typeCode = layers.ICMPv6TypeMLDv2MulticastListenerReportMessageV2
	icmpLayer := &layers.ICMPv6{
		TypeCode: typeCode << 8, // ICMPv6TypeCodes are >> 8, reverse
	}
	icmpLayer.SetNetworkLayerForChecksum(ipLayer)
	mcastRecords := []layers.MLDv2MulticastAddressRecord{
		{
			RecordType:       recordType,
			MulticastAddress: net.ParseIP("ff02::1"),
		},
	}
	mldLayer := &layers.MLDv2MulticastListenerReportMessage{
		NumberOfMulticastAddressRecords: 1,
		MulticastAddressRecords:         mcastRecords,
	}

	// serialize to buffer
	err := gopacket.SerializeLayers(pktBuf, opts,
		ethLayer, ipLayer, icmpLayer, mldLayer)
	if err != nil {
		log.Fatal(err)
	}

	// create packet from buffer
	pkt := gopacket.NewPacket(pktBuf.Bytes(), layers.LayerTypeEthernet,
		gopacket.Default)

	// parse packet
	parseMld(pkt)
}

func TestParseMLDv2(t *testing.T) {
	var buf bytes.Buffer
	var want, got string

	// set device table
	devices = &dev.DeviceMap{}

	// test query and filter exclude report parsing
	testParseMLDv2Query()
	recordTypes := []layers.MLDv2MulticastAddressRecordType{
		layers.MLDv2MulticastAddressRecordTypeModeIsExcluded,
		layers.MLDv2MulticastAddressRecordTypeChangeToExcludeMode,
	}
	for _, rt := range recordTypes {
		testParseMLDv2Report(rt)
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
		"    IP: ::1                                      " +
		"(age: -1, pkts: 0)\n" +
		"  Multicast Addresses:\n" +
		"    IP: ff02::1                                  " +
		"(age: -1, pkts: 0)\n\n"
	got = buf.String()
	if got != want {
		t.Errorf("got = %s; want = %s", got, want)
	}
	buf.Reset()

	// test filter include report parsing
	testParseMLDv2Query()
	recordTypes = []layers.MLDv2MulticastAddressRecordType{
		layers.MLDv2MulticastAddressRecordTypeModeIsIncluded,
		layers.MLDv2MulticastAddressRecordTypeChangeToIncludeMode,
	}
	for _, rt := range recordTypes {
		testParseMLDv2Report(rt)
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
		"    IP: ::1                                      " +
		"(age: -1, pkts: 0)\n\n"
	got = buf.String()
	if got != want {
		t.Errorf("got = %s; want = %s", got, want)
	}
}
