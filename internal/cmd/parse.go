package cmd

import (
	"github.com/google/gopacket"
)

// getMacs is a helper for getting src and dst mac addresses of packet
func getMacs(packet gopacket.Packet) (gopacket.Endpoint, gopacket.Endpoint) {
	var linkSrc, linkDst gopacket.Endpoint

	if link := packet.LinkLayer(); link != nil {
		// extract MAC addresses
		linkSrc, linkDst = link.LinkFlow().Endpoints()
	}

	return linkSrc, linkDst
}

// getIps is a helper for getting src and dst ip addresses of packet
func getIps(packet gopacket.Packet) (gopacket.Endpoint, gopacket.Endpoint) {
	var netSrc, netDst gopacket.Endpoint

	if net := packet.NetworkLayer(); net != nil {
		// extract IP addresses
		netSrc, netDst = net.NetworkFlow().Endpoints()
	}

	return netSrc, netDst
}

// updateStatistics updates statistics
func updateStatistics(packet gopacket.Packet) {
	// get addresses
	linkSrc, linkDst := getMacs(packet)
	netSrc, netDst := getIps(packet)

	// increase packet counters
	devices.packets++
	if device := devices.Get(linkSrc); device != nil {
		timestamp := packet.Metadata().Timestamp

		// mac/device
		device.packets++
		device.setTimestamp(timestamp)

		// ip
		if ip := device.ips.Get(netSrc); ip != nil {
			ip.Packets++
			ip.setTimestamp(timestamp)
		}

		// mac peers
		if peer := device.macPeers[linkDst]; peer != nil {
			peer.Packets++
			peer.setTimestamp(timestamp)
		}

		// ip peers
		if peer := device.ipPeers[netDst]; peer != nil {
			peer.Packets++
			peer.setTimestamp(timestamp)
		}
	}
}

// parseSrcMac parses the source MAC address and adds it to device table
func parseSrcMac(packet gopacket.Packet) {
	linkSrc, _ := getMacs(packet)
	devices.add(linkSrc)
}

// parsePeers parses peer addresses and adds them to device table
func parsePeers(packet gopacket.Packet) {
	if !withPeers {
		return
	}
	linkSrc, linkDst := getMacs(packet)
	_, netDst := getIps(packet)

	dev := devices.Get(linkSrc)
	dev.addPeer(linkDst)
	dev.addPeer(netDst)
}

// parse parses the packet
func parse(packet gopacket.Packet) {
	// lock devices
	devices.Lock()

	// parse packet
	parseSrcMac(packet)
	parsePeers(packet)
	parseVlan(packet)
	parseVxlan(packet)
	parseGeneve(packet)
	parseArp(packet)
	parseNdp(packet)
	parseIgmp(packet)
	parseMld(packet)
	parseDhcp(packet)
	parseStp(packet)
	parsePlc(packet)
	updateStatistics(packet)

	// unlock devices
	devices.Unlock()

}
