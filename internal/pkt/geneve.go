package pkt

import (
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// parseGeneve parses Geneve headers
func parseGeneve(packet gopacket.Packet) {
	geneveLayer := packet.Layer(layers.LayerTypeGeneve)
	if geneveLayer != nil {
		debug("Geneve Header")
		geneve, _ := geneveLayer.(*layers.Geneve)
		linkSrc, _ := getMacs(packet)
		dev := devices.Add(linkSrc)
		g := dev.GENEVEs.Add(geneve.VNI)
		g.Type = "GENEVE"
		g.SetTimestamp(packet.Metadata().Timestamp)
		g.Packets++
	}
}
