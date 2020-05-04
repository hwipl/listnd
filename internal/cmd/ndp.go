package cmd

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// parseNdp parses neighbor discovery protocol packets
func parseNdp(packet gopacket.Packet) {
	nsolLayer := packet.Layer(layers.LayerTypeICMPv6NeighborSolicitation)
	if nsolLayer != nil {
		debug("Neighbor Solicitation")
		// neighbor solicitation, get src mac and src ip
		linkSrc, _ := getMacs(packet)
		netSrc, _ := getIps(packet)

		// add to table
		devices.addMacIP(linkSrc, netSrc)

		return
	}

	nadvLayer := packet.Layer(layers.LayerTypeICMPv6NeighborAdvertisement)
	if nadvLayer != nil {
		debug("Neighbor Advertisement")
		// neighbor advertisement, get src mac and target ip
		adv, _ := nadvLayer.(*layers.ICMPv6NeighborAdvertisement)
		targetIP := layers.NewIPEndpoint(adv.TargetAddress)
		linkSrc, _ := getMacs(packet)

		// add to table
		devices.addMacIP(linkSrc, targetIP)

		return
	}

	rsolLayer := packet.Layer(layers.LayerTypeICMPv6RouterSolicitation)
	if rsolLayer != nil {
		debug("Router Solicitation")
		// router solicitation, get src mac and src ip
		linkSrc, _ := getMacs(packet)
		netSrc, _ := getIps(packet)

		// add to table
		devices.addMacIP(linkSrc, netSrc)

		return
	}

	radvLayer := packet.Layer(layers.LayerTypeICMPv6RouterAdvertisement)
	if radvLayer != nil {
		debug("Router Advertisement")
		// router advertisement, get src mac and src ip
		linkSrc, _ := getMacs(packet)
		netSrc, _ := getIps(packet)

		// add to table
		devices.addMacIP(linkSrc, netSrc)

		// mark device as a router
		timestamp := packet.Metadata().Timestamp
		devices[linkSrc].router.enable()
		devices[linkSrc].router.setTimestamp(timestamp)

		// flush prefixes and refill with advertised ones
		adv, _ := radvLayer.(*layers.ICMPv6RouterAdvertisement)
		devices[linkSrc].router.clearPrefixes()
		for i := range adv.Options {
			if adv.Options[i].Type == layers.ICMPv6OptPrefixInfo {
				p := devices[linkSrc].router.addPrefix(
					adv.Options[i])
				p.setTimestamp(timestamp)
			}
		}
		return
	}
}
