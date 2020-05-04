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
		devices[linkSrc].addGeneve(geneve.VNI)
		devices[linkSrc].geneves[geneve.VNI].setTimestamp(
			packet.Metadata().Timestamp)
		devices[linkSrc].geneves[geneve.VNI].packets++
	}
}
