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
		dev := devices.Get(linkSrc)
		dev.addVlan(vlan.VLANIdentifier)
		dev.vlans[vlan.VLANIdentifier].setTimestamp(
			packet.Metadata().Timestamp)
		dev.vlans[vlan.VLANIdentifier].packets++
	}
}
