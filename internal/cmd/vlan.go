package cmd

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// parseVlan parses VLAN tags
func parseVlan(packet gopacket.Packet) {
	vlanLayer := packet.Layer(layers.LayerTypeDot1Q)
	if vlanLayer != nil {
		debug("VLAN Tag")
		vlan, _ := vlanLayer.(*layers.Dot1Q)
		linkSrc, _ := getMacs(packet)
		devices[linkSrc].addVlan(vlan.VLANIdentifier)
		devices[linkSrc].vlans[vlan.VLANIdentifier].setTimestamp(
			packet.Metadata().Timestamp)
		devices[linkSrc].vlans[vlan.VLANIdentifier].packets++
	}
}
