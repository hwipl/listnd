package pkt

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
			dev := devices.Add(linkSrc)
			v := dev.VXLANs.Add(vxlan.VNI)
			v.Type = "VXLAN"
			v.SetTimestamp(packet.Metadata().Timestamp)
			v.Packets++
		}
	}
}
