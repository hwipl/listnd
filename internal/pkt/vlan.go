package pkt

import (
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// parseVlan parses VLAN tags
func parseVlan(packet gopacket.Packet) {
	vlanLayer := packet.Layer(layers.LayerTypeDot1Q)
	if vlanLayer != nil {
		debug("VLAN Tag")
		vlan, _ := vlanLayer.(*layers.Dot1Q)
		linkSrc, _ := getMacs(packet)
		dev := devices.Add(linkSrc)
		v := dev.VLANs.Add(uint32(vlan.VLANIdentifier))
		v.Type = "VLAN"
		v.SetTimestamp(packet.Metadata().Timestamp)
		v.Packets++
	}
}
