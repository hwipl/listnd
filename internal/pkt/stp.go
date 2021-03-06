package pkt

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// parseStp parses stp packets
func parseStp(packet gopacket.Packet) {
	stpLayer := packet.Layer(layers.LayerTypeSTP)
	if stpLayer != nil {
		debug("STP packet")
		linkSrc, _ := getMacs(packet)

		// add device and mark this device as a bridge
		dev := devices.Add(linkSrc)
		dev.Bridge.Enable()
		dev.Bridge.SetTimestamp(packet.Metadata().Timestamp)
	}
}
