package pkt

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// parseArp parses ARP packets
func parseArp(packet gopacket.Packet) {
	arpLayer := packet.Layer(layers.LayerTypeARP)
	if arpLayer != nil {
		arp, _ := arpLayer.(*layers.ARP)

		// arp request or reply
		switch arp.Operation {
		case layers.ARPRequest:
			debug("ARP Request")
		case layers.ARPReply:
			debug("ARP Reply")
		}
		// get addresses
		linkSrc := layers.NewMACEndpoint(arp.SourceHwAddress)
		netSrc := layers.NewIPEndpoint(arp.SourceProtAddress)

		// add to table
		dev := devices.Add(linkSrc)
		dev.UCasts.Add(netSrc)
	}
}
