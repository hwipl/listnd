package cmd

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// parseVxlan parses VXLAN headers
func parseVxlan(packet gopacket.Packet) {
	vxlanLayer := packet.Layer(layers.LayerTypeVXLAN)
	if vxlanLayer != nil {
		debug("VXLAN Header")
		vxlan, _ := vxlanLayer.(*layers.VXLAN)
		if vxlan.ValidIDFlag {
			linkSrc, _ := getMacs(packet)
			dev := devices.Get(linkSrc)
			v := dev.vxlans.Add(vxlan.VNI)
			v.setTimestamp(packet.Metadata().Timestamp)
			v.packets++
		}
	}
}
