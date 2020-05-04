package cmd

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// parseIgmp parses igmp packets
func parseIgmp(packet gopacket.Packet) {
	igmpLayer := packet.Layer(layers.LayerTypeIGMP)
	if igmpLayer == nil {
		// no igmp message, stop
		return
	}
	linkSrc, _ := getMacs(packet)

	// add source IP to device
	netSrc, _ := getIps(packet)
	devices[linkSrc].addIP(netSrc)

	// igmp v1 or v2
	if igmp, ok := igmpLayer.(*layers.IGMPv1or2); ok {
		// parse message type
		switch igmp.Type {
		case layers.IGMPMembershipQuery:
			debug("IGMPv1or2 Membership Query")
			// queries are sent by routers, mark as router
			devices[linkSrc].router.enable()
			devices[linkSrc].router.setTimestamp(
				packet.Metadata().Timestamp)
		case layers.IGMPMembershipReportV1:
			debug("IGMPv1 Membership Report")
			// add IP
			devices[linkSrc].addIP(layers.NewIPEndpoint(
				igmp.GroupAddress))
		case layers.IGMPMembershipReportV2:
			debug("IGMPv2 Membership Report")
			// add IP
			devices[linkSrc].addIP(layers.NewIPEndpoint(
				igmp.GroupAddress))
		case layers.IGMPLeaveGroup:
			debug("IGMPv1or2 Leave Group")
			// remove IP
			devices[linkSrc].delIP(layers.NewIPEndpoint(
				igmp.GroupAddress))
		}
	}

	// igmp v3
	if igmp, ok := igmpLayer.(*layers.IGMP); ok {
		if igmp.Type == layers.IGMPMembershipQuery {
			debug("IGMPv3 Membership Query")
			// queries are sent by routers, mark as router
			devices[linkSrc].router.enable()
			devices[linkSrc].router.setTimestamp(
				packet.Metadata().Timestamp)
		}

		if igmp.Type == layers.IGMPMembershipReportV3 {
			debug("IGMPv3 Membership Report")
			// parse multicast addresses and add/remove them
			for _, v := range igmp.GroupRecords {
				switch v.Type {
				case layers.IGMPIsEx, layers.IGMPToEx:
					// add IP
					devices[linkSrc].addIP(
						layers.NewIPEndpoint(
							v.MulticastAddress))
				case layers.IGMPIsIn, layers.IGMPToIn:
					// remove IP
					devices[linkSrc].delIP(
						layers.NewIPEndpoint(
							v.MulticastAddress))
				}
			}
		}
	}
}
