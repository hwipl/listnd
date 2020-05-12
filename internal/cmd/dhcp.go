package cmd

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// parseDhcp parses dhcp packets
func parseDhcp(packet gopacket.Packet) {
	// DHCP v4
	dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
	if dhcpLayer != nil {
		dhcp, _ := dhcpLayer.(*layers.DHCPv4)
		linkSrc, _ := getMacs(packet)

		// add device
		devices.Add(linkSrc)
		if dhcp.Operation == layers.DHCPOpRequest {
			debug("DHCP Request")
			return
		}
		if dhcp.Operation == layers.DHCPOpReply {
			debug("DHCP Reply")
			// mark this device as dhcp server
			dev := devices.Get(linkSrc)
			dev.dhcp.enable()
			dev.dhcp.setTimestamp(packet.Metadata().Timestamp)
		}
	}

	// DHCP v6
	dhcpv6Layer := packet.Layer(layers.LayerTypeDHCPv6)
	if dhcpv6Layer != nil {
		dhcp, _ := dhcpv6Layer.(*layers.DHCPv6)
		linkSrc, _ := getMacs(packet)
		netSrc, _ := getIps(packet)
		dev := devices.Get(linkSrc)
		dev.ucasts.Add(netSrc)
		timestamp := packet.Metadata().Timestamp

		// parse message type to determine if server or client
		switch dhcp.MsgType {
		case layers.DHCPv6MsgTypeSolicit:
			debug("DHCPv6 Solicit")
		case layers.DHCPv6MsgTypeAdverstise:
			debug("DHCPv6 Advertise")
		case layers.DHCPv6MsgTypeRequest:
			debug("DHCPv6 Request")
			// server
			dev.dhcp.enable()
			dev.dhcp.setTimestamp(timestamp)
		case layers.DHCPv6MsgTypeConfirm:
			debug("DHCPv6 Confirm")
		case layers.DHCPv6MsgTypeRenew:
			debug("DHCPv6 Renew")
		case layers.DHCPv6MsgTypeRebind:
			debug("DHCPv6 Rebind")
		case layers.DHCPv6MsgTypeReply:
			debug("DHCPv6 Reply")
			// server
			dev.dhcp.enable()
			dev.dhcp.setTimestamp(timestamp)
		case layers.DHCPv6MsgTypeRelease:
			debug("DHCPv6 Release")
		case layers.DHCPv6MsgTypeDecline:
			debug("DHCPv6 Decline")
		case layers.DHCPv6MsgTypeReconfigure:
			debug("DHCPv6 Reconfigure")
			// server
			dev.dhcp.enable()
			dev.dhcp.setTimestamp(timestamp)
		case layers.DHCPv6MsgTypeInformationRequest:
			debug("DHCPv6 Information Request")
		case layers.DHCPv6MsgTypeRelayForward:
			debug("DHCPv6 Relay Forward")
		case layers.DHCPv6MsgTypeRelayReply:
			debug("DHCPv6 Relay Reply")
			// server
			dev.dhcp.enable()
			dev.dhcp.setTimestamp(timestamp)
		}
	}
}
