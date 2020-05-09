package cmd

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// parseGeneve parses Geneve headers
func parseGeneve(packet gopacket.Packet) {
	geneveLayer := packet.Layer(layers.LayerTypeGeneve)
	if geneveLayer != nil {
		debug("Geneve Header")
		geneve, _ := geneveLayer.(*layers.Geneve)
		linkSrc, _ := getMacs(packet)
		dev := devices.Get(linkSrc)
		g := dev.geneves.Add(geneve.VNI)
		g.setTimestamp(packet.Metadata().Timestamp)
		g.packets++
	}
}
