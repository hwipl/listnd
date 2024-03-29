package pkt

import (
	"fmt"
	"io"
	"os"

	"github.com/gopacket/gopacket"

	"github.com/hwipl/listnd/internal/dev"
)

var (
	debugMode bool
	debugOut  io.Writer = os.Stdout
	withPeers bool
	devices   *dev.DeviceMap
)

// SetDebug enables or disables debug output
func SetDebug(enable bool) {
	debugMode = enable
}

// SetPeers enables or disabled parsing of peer addresses
func SetPeers(enable bool) {
	withPeers = enable
}

// SetDevices sets the device table
func SetDevices(devs *dev.DeviceMap) {
	devices = devs
}

// debug prints text if in debug mode
func debug(text string) {
	if debugMode {
		fmt.Fprintln(debugOut, text)
	}
}

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
	devices.Packets++
	if device := devices.Get(linkSrc); device != nil {
		timestamp := packet.Metadata().Timestamp

		// mac/device
		device.Packets++
		device.SetTimestamp(timestamp)

		// unicast ips
		if ip := device.UCasts.Get(netSrc); ip != nil {
			ip.Packets++
			ip.SetTimestamp(timestamp)
		}

		// mac peers
		if peer := device.MACPeers.Get(linkDst); peer != nil {
			peer.Packets++
			peer.SetTimestamp(timestamp)
		}

		// ip peers
		if peer := device.IPPeers.Get(netDst); peer != nil {
			peer.Packets++
			peer.SetTimestamp(timestamp)
		}
	}
}

// parseSrcMac parses the source MAC address and adds it to device table
func parseSrcMac(packet gopacket.Packet) {
	linkSrc, _ := getMacs(packet)
	devices.Add(linkSrc)
}

// parsePeers parses peer addresses and adds them to device table
func parsePeers(packet gopacket.Packet) {
	if !withPeers {
		return
	}
	linkSrc, linkDst := getMacs(packet)
	_, netDst := getIps(packet)

	dev := devices.Get(linkSrc)
	dev.MACPeers.Add(linkDst)
	dev.IPPeers.Add(netDst)
}

// Parse parses the packet
func Parse(packet gopacket.Packet) {
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
