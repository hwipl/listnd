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
		dev.addGeneve(geneve.VNI)
		dev.geneves[geneve.VNI].setTimestamp(
			packet.Metadata().Timestamp)
		dev.geneves[geneve.VNI].packets++
	}
}
