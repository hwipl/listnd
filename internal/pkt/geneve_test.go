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

func TestParseGeneve(t *testing.T) {
	var buf bytes.Buffer
	var want, got string

	// set device table
	devices = &dev.DeviceMap{}

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
		SrcPort: 6081,
		DstPort: 6081,
	}
	udpLayer.SetNetworkLayerForChecksum(ipLayer)
	// geneve layer does not have a SerializeTo() method,
	// build dummy geneve payload
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |Ver|  Opt Len  |O|C|    Rsvd.  |          Protocol Type        |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |        Virtual Network Identifier (VNI)       |    Reserved   |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Variable Length Options                    |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	geneveLayer := gopacket.Payload([]byte{
		0, 0, 0, 0,
		0, 0, 42, 0,
	})

	// serialize to buffer
	err := gopacket.SerializeLayers(pktBuf, opts,
		ethLayer, ipLayer, udpLayer, geneveLayer)
	if err != nil {
		log.Fatal(err)
	}

	// create packet from buffer
	pkt := gopacket.NewPacket(pktBuf.Bytes(), layers.LayerTypeEthernet,
		gopacket.Default)

	// parse packet and check output
	parseGeneve(pkt)
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
		"    GENEVE: 42                                   " +
		"(age: -1, pkts: 1)\n\n"
	got = buf.String()
	if got != want {
		t.Errorf("got = %s; want = %s", got, want)
	}
}
