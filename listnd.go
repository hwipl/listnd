package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

/* variable definitions */
var (
	/* network device map */
	packets     int
	devicesLock = &sync.Mutex{}
	devices     = make(deviceMap)

	/* pcap settings */
	pcapPromisc bool   = true
	pcapDevice  string = "eth0"
	pcapSnaplen int    = 1024
	pcapTimeout int    = 1
	pcapHandle  *pcap.Handle
	pcapErr     error

	/* parsing/output settings */
	debugMode bool = false
	withPeers bool = false
)

/*
 ********************
 *** DEVICE TABLE ***
 ********************
 */

/* struct for timestamps */
type timeInfo struct {
	timestamp time.Time
}

/* set timestamp */
func (t *timeInfo) setTimestamp(timestamp time.Time) {
	t.timestamp = timestamp
}

/* get seconds since timestamp */
func (t *timeInfo) getAge() float64 {
	if t.timestamp == (time.Time{}) {
		return -1
	}
	return time.Since(t.timestamp).Seconds()
}

/* struct for device properties */
type propInfo struct {
	enabled bool
}

/* enable device property */
func (p *propInfo) enable() {
	p.enabled = true
}

/* disable device property */
func (p *propInfo) disable() {
	p.enabled = false
}

/* check if device property is enabled */
func (p *propInfo) isEnabled() bool {
	if p != nil && p.enabled {
		return true
	}
	return false
}

/* struct for vlan information */
type vlanInfo struct {
	timeInfo
	vlan    uint16
	packets int
}

/* struct for vxlan information */
type vxlanInfo struct {
	timeInfo
	vxlan   uint32
	packets int
}

/* struct for ip addresses of devices on the network */
type ipInfo struct {
	timeInfo
	ip      gopacket.Endpoint
	packets int
}

/* struct for router information of devices on the network */
type routerInfo struct {
	propInfo
	timeInfo
	prefixes []*prefixInfo
}

/* struct for router's prefix information */
type prefixInfo struct {
	timeInfo
	prefix layers.ICMPv6Option
}

/* struct for powerline information */
type powerlineInfo struct {
	propInfo
	timeInfo
}

/* struct for dhcp information */
type dhcpInfo struct {
	propInfo
	timeInfo
}

/* struct for bridge information */
type bridgeInfo struct {
	propInfo
	timeInfo
}

/* struct for devices found on the network */
type deviceInfo struct {
	timeInfo
	mac       gopacket.Endpoint
	vlans     map[uint16]*vlanInfo
	vxlans    map[uint32]*vxlanInfo
	powerline powerlineInfo
	bridge    bridgeInfo
	dhcp      dhcpInfo
	router    routerInfo
	packets   int
	ips       map[gopacket.Endpoint]*ipInfo
	macPeers  map[gopacket.Endpoint]*ipInfo
	ipPeers   map[gopacket.Endpoint]*ipInfo
}

/* device table definition */
type deviceMap map[gopacket.Endpoint]*deviceInfo

/* clear prefixes in router info */
func (r *routerInfo) clearPrefixes() {
	r.prefixes = nil
}

/* add prefix to router info */
func (r *routerInfo) addPrefix(prefix layers.ICMPv6Option) *prefixInfo {
	p := prefixInfo{}
	p.prefix = prefix
	r.prefixes = append(r.prefixes, &p)
	return &p
}

/* get prefixes from router info */
func (r *routerInfo) getPrefixes() []*prefixInfo {
	return r.prefixes
}

/* add a vlan to a device */
func (d *deviceInfo) addVlan(vlanID uint16) {
	/* add entry if it does not exist */
	if d.vlans[vlanID] == nil {
		debug("Adding new vlan to an entry")
		vlan := vlanInfo{}
		vlan.vlan = vlanID
		d.vlans[vlanID] = &vlan
	}
}

/* add a vxlan to a device */
func (d *deviceInfo) addVxlan(vni uint32) {
	/* add entry if it does not exist */
	if d.vxlans[vni] == nil {
		debug("Adding new vxlan to an entry")
		vxlan := vxlanInfo{}
		vxlan.vxlan = vni
		d.vxlans[vni] = &vxlan
	}
}

/* add an ip address to a device */
func (d *deviceInfo) addIP(netAddr gopacket.Endpoint) {
	/* make sure address is valid */
	if !endpointIsValidIP(netAddr) {
		return
	}

	/* add entry if it does not exist */
	if d.ips[netAddr] == nil {
		debug("Adding new ip to an entry")
		ip := ipInfo{}
		ip.ip = netAddr
		d.ips[netAddr] = &ip
	}
}

/* remove an ip address from a device */
func (d *deviceInfo) delIP(netAddr gopacket.Endpoint) {
	/* make sure address is valid */
	if !endpointIsValidIP(netAddr) {
		return
	}

	/* remove entry if it exists */
	if d.ips[netAddr] != nil {
		debug("Deleting ip from an entry")
		delete(d.ips, netAddr)
	}
}

/* add a peer address to a device */
func (d *deviceInfo) addPeer(addr gopacket.Endpoint) {
	switch addr.EndpointType() {
	case layers.EndpointMAC:
		if d.macPeers[addr] == nil {
			debug("Adding new mac peer to an entry")
			// TODO: rename to addrInfo? add macInfo?
			ip := ipInfo{}
			ip.ip = addr
			d.macPeers[addr] = &ip
		}
	case layers.EndpointIPv4, layers.EndpointIPv6:
		if d.ipPeers[addr] == nil {
			debug("Adding new ip peer to an entry")
			ip := ipInfo{}
			ip.ip = addr
			d.ipPeers[addr] = &ip
		}
	}
}

/* add a device to the device table */
func (d deviceMap) add(linkAddr gopacket.Endpoint) {
	/* create table entries if necessary */
	if d[linkAddr] == nil {
		debug("Adding new entry")
		device := deviceInfo{}
		device.mac = linkAddr
		device.vlans = make(map[uint16]*vlanInfo)
		device.vxlans = make(map[uint32]*vxlanInfo)
		device.ips = make(map[gopacket.Endpoint]*ipInfo)
		device.macPeers = make(map[gopacket.Endpoint]*ipInfo)
		device.ipPeers = make(map[gopacket.Endpoint]*ipInfo)
		d[linkAddr] = &device
	}
}

/* add a device table entry with mac and ip address*/
func (d deviceMap) addMacIP(linkAddr, netAddr gopacket.Endpoint) {
	d.add(linkAddr)
	d[linkAddr].addIP(netAddr)
}

/* check if IP address in endpoint is valid */
var addrZero gopacket.Endpoint
var addrUnspecv4 = layers.NewIPEndpoint(net.ParseIP("0.0.0.0"))
var addrUnspecv6 = layers.NewIPEndpoint(net.ParseIP("::"))

func endpointIsValidIP(e gopacket.Endpoint) bool {
	if e == addrZero || e == addrUnspecv4 || e == addrUnspecv6 {
		return false
	}

	return true
}

/*
 ************************
 *** PROTOCOL PARSING ***
 ************************
 */

/* helper for getting src and dst mac addresses of packet */
func getMacs(packet gopacket.Packet) (gopacket.Endpoint, gopacket.Endpoint) {
	var linkSrc, linkDst gopacket.Endpoint

	if link := packet.LinkLayer(); link != nil {
		/* extract MAC addresses */
		linkSrc, linkDst = link.LinkFlow().Endpoints()
	}

	return linkSrc, linkDst
}

/* helper for getting src and dst ip addresses of packet */
func getIps(packet gopacket.Packet) (gopacket.Endpoint, gopacket.Endpoint) {
	var netSrc, netDst gopacket.Endpoint

	if net := packet.NetworkLayer(); net != nil {
		/* extract IP addresses */
		netSrc, netDst = net.NetworkFlow().Endpoints()
	}

	return netSrc, netDst
}

/* update statistics */
func updateStatistics(packet gopacket.Packet) {
	/* get addresses */
	linkSrc, linkDst := getMacs(packet)
	netSrc, netDst := getIps(packet)

	/* increase packet counters */
	packets++
	if device := devices[linkSrc]; device != nil {
		timestamp := packet.Metadata().Timestamp

		/* mac/device */
		device.packets++
		device.setTimestamp(timestamp)

		/* ip */
		if ip := device.ips[netSrc]; ip != nil {
			ip.packets++
			ip.setTimestamp(timestamp)
		}

		/* mac peers */
		if peer := device.macPeers[linkDst]; peer != nil {
			peer.packets++
			peer.setTimestamp(timestamp)
		}

		/* ip peers */
		if peer := device.ipPeers[netDst]; peer != nil {
			peer.packets++
			peer.setTimestamp(timestamp)
		}
	}
}

/* parse the source MAC address and add it to device table */
func parseSrcMac(packet gopacket.Packet) {
	linkSrc, _ := getMacs(packet)
	devices.add(linkSrc)
}

/* parse peer addresses and add them to device table */
func parsePeers(packet gopacket.Packet) {
	if !withPeers {
		return
	}
	linkSrc, linkDst := getMacs(packet)
	_, netDst := getIps(packet)

	devices[linkSrc].addPeer(linkDst)
	devices[linkSrc].addPeer(netDst)
}

/* parse VLAN tags */
func parseVlan(packet gopacket.Packet) {
	vlanLayer := packet.Layer(layers.LayerTypeDot1Q)
	if vlanLayer != nil {
		debug("VLAN Tag")
		vlan, _ := vlanLayer.(*layers.Dot1Q)
		linkSrc, _ := getMacs(packet)
		devices[linkSrc].addVlan(vlan.VLANIdentifier)
		devices[linkSrc].vlans[vlan.VLANIdentifier].setTimestamp(
			packet.Metadata().Timestamp)
		devices[linkSrc].vlans[vlan.VLANIdentifier].packets++
	}
}

/* parse VXLAN header */
func parseVxlan(packet gopacket.Packet) {
	vxlanLayer := packet.Layer(layers.LayerTypeVXLAN)
	if vxlanLayer != nil {
		debug("VXLAN Header")
		vxlan, _ := vxlanLayer.(*layers.VXLAN)
		if vxlan.ValidIDFlag {
			linkSrc, _ := getMacs(packet)
			devices[linkSrc].addVxlan(vxlan.VNI)
			devices[linkSrc].vxlans[vxlan.VNI].setTimestamp(
				packet.Metadata().Timestamp)
			devices[linkSrc].vxlans[vxlan.VNI].packets++
		}
	}
}

/* parse ARP packets */
func parseArp(packet gopacket.Packet) {
	arpLayer := packet.Layer(layers.LayerTypeARP)
	if arpLayer != nil {
		arp, _ := arpLayer.(*layers.ARP)

		/* arp request or reply */
		switch arp.Operation {
		case layers.ARPRequest:
			debug("ARP Request")
		case layers.ARPReply:
			debug("ARP Reply")
		}
		/* get addresses */
		linkSrc := layers.NewMACEndpoint(arp.SourceHwAddress)
		netSrc := layers.NewIPEndpoint(arp.SourceProtAddress)

		/* add to table */
		devices.addMacIP(linkSrc, netSrc)
	}
}

/* parse neighbor discovery protocol packets */
func parseNdp(packet gopacket.Packet) {
	nsolLayer := packet.Layer(layers.LayerTypeICMPv6NeighborSolicitation)
	if nsolLayer != nil {
		debug("Neighbor Solicitation")
		/* neighbor solicitation, get src mac and src ip */
		linkSrc, _ := getMacs(packet)
		netSrc, _ := getIps(packet)

		/* add to table */
		devices.addMacIP(linkSrc, netSrc)

		return
	}

	nadvLayer := packet.Layer(layers.LayerTypeICMPv6NeighborAdvertisement)
	if nadvLayer != nil {
		debug("Neighbor Advertisement")
		/* neighbor advertisement, get src mac and target ip */
		adv, _ := nadvLayer.(*layers.ICMPv6NeighborAdvertisement)
		targetIP := layers.NewIPEndpoint(adv.TargetAddress)
		linkSrc, _ := getMacs(packet)

		/* add to table */
		devices.addMacIP(linkSrc, targetIP)

		return
	}

	rsolLayer := packet.Layer(layers.LayerTypeICMPv6RouterSolicitation)
	if rsolLayer != nil {
		debug("Router Solicitation")
		/* router solicitation, get src mac and src ip */
		linkSrc, _ := getMacs(packet)
		netSrc, _ := getIps(packet)

		/* add to table */
		devices.addMacIP(linkSrc, netSrc)

		return
	}

	radvLayer := packet.Layer(layers.LayerTypeICMPv6RouterAdvertisement)
	if radvLayer != nil {
		debug("Router Advertisement")
		/* router advertisement, get src mac and src ip */
		linkSrc, _ := getMacs(packet)
		netSrc, _ := getIps(packet)

		/* add to table */
		devices.addMacIP(linkSrc, netSrc)

		/* mark device as a router */
		timestamp := packet.Metadata().Timestamp
		devices[linkSrc].router.enable()
		devices[linkSrc].router.setTimestamp(timestamp)

		/* flush prefixes and refill with advertised ones */
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

/* parse igmp packets */
func parseIgmp(packet gopacket.Packet) {
	igmpLayer := packet.Layer(layers.LayerTypeIGMP)
	if igmpLayer == nil {
		/* no igmp message, stop */
		return
	}
	linkSrc, _ := getMacs(packet)

	/* add source IP to device */
	netSrc, _ := getIps(packet)
	devices[linkSrc].addIP(netSrc)

	/* igmp v1 or v2 */
	if igmp, ok := igmpLayer.(*layers.IGMPv1or2); ok {
		/* parse message type */
		switch igmp.Type {
		case layers.IGMPMembershipQuery:
			debug("IGMPv1or2 Membership Query")
			/* queries are sent by routers, mark as router */
			devices[linkSrc].router.enable()
			devices[linkSrc].router.setTimestamp(
				packet.Metadata().Timestamp)
		case layers.IGMPMembershipReportV1:
			debug("IGMPv1 Membership Report")
			/* add IP */
			devices[linkSrc].addIP(layers.NewIPEndpoint(
				igmp.GroupAddress))
		case layers.IGMPMembershipReportV2:
			debug("IGMPv2 Membership Report")
			/* add IP */
			devices[linkSrc].addIP(layers.NewIPEndpoint(
				igmp.GroupAddress))
		case layers.IGMPLeaveGroup:
			debug("IGMPv1or2 Leave Group")
			/* remove IP */
			devices[linkSrc].delIP(layers.NewIPEndpoint(
				igmp.GroupAddress))
		}
	}

	/* igmp v3 */
	if igmp, ok := igmpLayer.(*layers.IGMP); ok {
		if igmp.Type == layers.IGMPMembershipQuery {
			debug("IGMPv3 Membership Query")
			/* queries are sent by routers, mark as router */
			devices[linkSrc].router.enable()
			devices[linkSrc].router.setTimestamp(
				packet.Metadata().Timestamp)
		}

		if igmp.Type == layers.IGMPMembershipReportV3 {
			debug("IGMPv3 Membership Report")
			/* parse multicast addresses and add/remove them */
			for _, v := range igmp.GroupRecords {
				switch v.Type {
				case layers.IGMPIsEx, layers.IGMPToEx:
					/* add IP */
					devices[linkSrc].addIP(
						layers.NewIPEndpoint(
							v.MulticastAddress))
				case layers.IGMPIsIn, layers.IGMPToIn:
					/* remove IP */
					devices[linkSrc].delIP(
						layers.NewIPEndpoint(
							v.MulticastAddress))
				}
			}
		}
	}
}

/* parse mld packets */
const mldv2IsEx = layers.MLDv2MulticastAddressRecordTypeModeIsExcluded
const mldv2ToEx = layers.MLDv2MulticastAddressRecordTypeChangeToExcludeMode
const mldv2IsIn = layers.MLDv2MulticastAddressRecordTypeModeIsIncluded
const mldv2ToIn = layers.MLDv2MulticastAddressRecordTypeChangeToIncludeMode

func parseMld(packet gopacket.Packet) {
	/* MLDv1 */
	qlv1 := packet.Layer(layers.LayerTypeMLDv1MulticastListenerQuery)
	if qlv1 != nil {
		debug("MLDv1 Query Message")
		/* queries are sent by routers, mark as router */
		linkSrc, _ := getMacs(packet)
		netSrc, _ := getIps(packet)
		devices[linkSrc].addIP(netSrc)
		devices[linkSrc].router.enable()
		devices[linkSrc].router.setTimestamp(
			packet.Metadata().Timestamp)
		return
	}

	dlv1 := packet.Layer(layers.LayerTypeMLDv1MulticastListenerDone)
	if dlv1 != nil {
		debug("MLDv1 Done Message")
		/* parse and remove multicast address */
		done, _ := dlv1.(*layers.MLDv1MulticastListenerDoneMessage)
		linkSrc, _ := getMacs(packet)
		netSrc, _ := getIps(packet)
		devices[linkSrc].addIP(netSrc)
		devices[linkSrc].delIP(
			layers.NewIPEndpoint(done.MulticastAddress))
		return
	}

	rlv1 := packet.Layer(layers.LayerTypeMLDv1MulticastListenerReport)
	if rlv1 != nil {
		debug("MLDv1 Report Message")
		/* parse and add multicast address */
		report, _ := rlv1.(*layers.MLDv1MulticastListenerReportMessage)
		linkSrc, _ := getMacs(packet)
		netSrc, _ := getIps(packet)
		devices[linkSrc].addIP(netSrc)
		devices[linkSrc].addIP(
			layers.NewIPEndpoint(report.MulticastAddress))
		return
	}

	/* MLDv2 */
	qlv2 := packet.Layer(layers.LayerTypeMLDv2MulticastListenerQuery)
	if qlv2 != nil {
		debug("MLDv2 Query Message")
		/* queries are sent by routers, mark as router */
		linkSrc, _ := getMacs(packet)
		netSrc, _ := getIps(packet)
		devices[linkSrc].addIP(netSrc)
		devices[linkSrc].router.enable()
		devices[linkSrc].router.setTimestamp(
			packet.Metadata().Timestamp)
		return
	}

	rlv2 := packet.Layer(layers.LayerTypeMLDv2MulticastListenerReport)
	if rlv2 != nil {
		debug("MLDv2 Report Message")
		report, _ := rlv2.(*layers.MLDv2MulticastListenerReportMessage)
		linkSrc, _ := getMacs(packet)
		netSrc, _ := getIps(packet)
		devices[linkSrc].addIP(netSrc)

		/* parse multicast addresses and add/remove them */
		for _, v := range report.MulticastAddressRecords {
			switch v.RecordType {
			case mldv2IsEx, mldv2ToEx:
				/* add IP */
				devices[linkSrc].addIP(layers.NewIPEndpoint(
					v.MulticastAddress))
			case mldv2IsIn, mldv2ToIn:
				/* remove IP */
				devices[linkSrc].delIP(layers.NewIPEndpoint(
					v.MulticastAddress))
			}
		}
		return
	}
}

/* parse dhcp packets */
func parseDhcp(packet gopacket.Packet) {
	/* DHCP v4 */
	dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
	if dhcpLayer != nil {
		dhcp, _ := dhcpLayer.(*layers.DHCPv4)
		linkSrc, _ := getMacs(packet)

		/* add device */
		devices.add(linkSrc)
		if dhcp.Operation == layers.DHCPOpRequest {
			debug("DHCP Request")
			return
		}
		if dhcp.Operation == layers.DHCPOpReply {
			debug("DHCP Reply")
			/* mark this device as dhcp server */
			devices[linkSrc].dhcp.enable()
			devices[linkSrc].dhcp.setTimestamp(
				packet.Metadata().Timestamp)
		}
	}

	/* DHCP v6 */
	dhcpv6Layer := packet.Layer(layers.LayerTypeDHCPv6)
	if dhcpv6Layer != nil {
		dhcp, _ := dhcpv6Layer.(*layers.DHCPv6)
		linkSrc, _ := getMacs(packet)
		netSrc, _ := getIps(packet)
		devices[linkSrc].addIP(netSrc)
		timestamp := packet.Metadata().Timestamp

		/* parse message type to determine if server or client */
		switch dhcp.MsgType {
		case layers.DHCPv6MsgTypeSolicit:
			debug("DHCPv6 Solicit")
		case layers.DHCPv6MsgTypeAdverstise:
			debug("DHCPv6 Advertise")
		case layers.DHCPv6MsgTypeRequest:
			debug("DHCPv6 Request")
			/* server */
			devices[linkSrc].dhcp.enable()
			devices[linkSrc].dhcp.setTimestamp(timestamp)
		case layers.DHCPv6MsgTypeConfirm:
			debug("DHCPv6 Confirm")
		case layers.DHCPv6MsgTypeRenew:
			debug("DHCPv6 Renew")
		case layers.DHCPv6MsgTypeRebind:
			debug("DHCPv6 Rebind")
		case layers.DHCPv6MsgTypeReply:
			debug("DHCPv6 Reply")
			/* server */
			devices[linkSrc].dhcp.enable()
			devices[linkSrc].dhcp.setTimestamp(timestamp)
		case layers.DHCPv6MsgTypeRelease:
			debug("DHCPv6 Release")
		case layers.DHCPv6MsgTypeDecline:
			debug("DHCPv6 Decline")
		case layers.DHCPv6MsgTypeReconfigure:
			debug("DHCPv6 Reconfigure")
			/* server */
			devices[linkSrc].dhcp.enable()
			devices[linkSrc].dhcp.setTimestamp(timestamp)
		case layers.DHCPv6MsgTypeInformationRequest:
			debug("DHCPv6 Information Request")
		case layers.DHCPv6MsgTypeRelayForward:
			debug("DHCPv6 Relay Forward")
		case layers.DHCPv6MsgTypeRelayReply:
			debug("DHCPv6 Relay Reply")
			/* server */
			devices[linkSrc].dhcp.enable()
			devices[linkSrc].dhcp.setTimestamp(timestamp)
		}
	}
}

/* parse stp packets */
func parseStp(packet gopacket.Packet) {
	stpLayer := packet.Layer(layers.LayerTypeSTP)
	if stpLayer != nil {
		debug("STP packet")
		linkSrc, _ := getMacs(packet)

		/* add device and mark this device as a bridge */
		devices.add(linkSrc)
		devices[linkSrc].bridge.enable()
		devices[linkSrc].bridge.setTimestamp(
			packet.Metadata().Timestamp)
	}
}

/* parse plc (power-line communication/homeplug) packets */
func parsePlc(packet gopacket.Packet) {
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer != nil {
		eth, _ := ethLayer.(*layers.Ethernet)
		if eth.EthernetType == 0x88e1 || eth.EthernetType == 0x8912 {
			debug("PLC packet")
			linkSrc, _ := getMacs(packet)

			/* add device and mark this device as a powerline */
			devices.add(linkSrc)
			devices[linkSrc].powerline.enable()
			devices[linkSrc].powerline.setTimestamp(
				packet.Metadata().Timestamp)
		}
	}
}

/*
 **********************
 *** CONSOLE OUTPUT ***
 **********************
 */

/* debug output */
func debug(text string) {
	if debugMode {
		fmt.Println(text)
	}
}

/* print router information in device table */
func printRouter(device *deviceInfo) {
	routerFmt := "    Router: %-36t (age: %.f)\n"
	prefixFmt := "      Prefix: %-34s (age: %.f)\n"

	if !device.router.isEnabled() {
		return
	}
	fmt.Printf(routerFmt, device.router.isEnabled(),
		device.router.getAge())
	for _, prefix := range device.router.getPrefixes() {
		pLen := uint8(prefix.prefix.Data[0])
		p := net.IP(prefix.prefix.Data[14:])
		ps := fmt.Sprintf("%v/%v", p, pLen)
		fmt.Printf(prefixFmt, ps, prefix.getAge())
	}
}

/* print dhcp information in device table */
func printDhcp(device *deviceInfo) {
	dhcpFmt := "    DHCP: %-38s (age: %.f)\n"
	dhcpRole := "server"

	if !device.dhcp.isEnabled() {
		return
	}
	fmt.Printf(dhcpFmt, dhcpRole, device.dhcp.getAge())
}

/* print bridge information in device table */
func printBridge(device *deviceInfo) {
	bridgeFmt := "    Bridge: %-36t (age: %.f)\n"

	if !device.bridge.isEnabled() {
		return
	}
	fmt.Printf(bridgeFmt, device.bridge.isEnabled(),
		device.bridge.getAge())
}

/* print powerline information in device table */
func printPowerline(device *deviceInfo) {
	powerlineFmt := "    Powerline: %-33t (age: %.f)\n"

	if !device.powerline.isEnabled() {
		return
	}
	fmt.Printf(powerlineFmt, device.powerline.isEnabled(),
		device.powerline.getAge())
}

/* print vlan information in device table */
func printVlans(device *deviceInfo) {
	vlanFmt := "    VLAN: %-38d (age: %.f, pkts: %d)\n"

	if len(device.vlans) == 0 {
		return
	}
	for _, vlan := range device.vlans {
		/* print VLAN info */
		fmt.Printf(vlanFmt, vlan.vlan, vlan.getAge(),
			vlan.packets)
	}
}

/* print vxlan information in device table */
func printVxlans(device *deviceInfo) {
	vxlanFmt := "    VXLAN: %-37d (age: %.f, pkts: %d)\n"

	if len(device.vxlans) == 0 {
		return
	}
	for _, vxlan := range device.vxlans {
		/* print VLAN info */
		fmt.Printf(vxlanFmt, vxlan.vxlan, vxlan.getAge(),
			vxlan.packets)
	}
}

/* print device properties in device table */
func printProperties(device *deviceInfo) {
	propsHeader := "  Properties:\n"

	/* make sure any properties are present */
	if !device.bridge.isEnabled() &&
		!device.dhcp.isEnabled() &&
		!device.router.isEnabled() &&
		!device.powerline.isEnabled() &&
		len(device.vlans) == 0 &&
		len(device.vxlans) == 0 {
		return
	}
	/* start with header */
	fmt.Printf(propsHeader)

	/* print device properties */
	printBridge(device)
	printDhcp(device)
	printRouter(device)
	printPowerline(device)
	printVlans(device)
	printVxlans(device)
}

/* print ip information in device table */
func _printIps(ips []*ipInfo) {
	ipFmt := "    IP: %-40s (age: %.f, pkts: %d)\n"
	for _, info := range ips {
		fmt.Printf(ipFmt, info.ip, info.getAge(), info.packets)
	}
}

/* print ip addresses in device table */
func printIps(device *deviceInfo) {
	multicastHeader := "  Multicast Addresses:\n"
	unicastHeader := "  Unicast Addresses:\n"
	var multicasts []*ipInfo
	var unicasts []*ipInfo

	/* search for ucast and mcast addresses */
	for ip, info := range device.ips {
		if net.IP(ip.Raw()).IsMulticast() {
			multicasts = append(multicasts, info)
			continue
		}
		unicasts = append(unicasts, info)
	}

	/* print unicast addresses */
	if len(unicasts) > 0 {
		fmt.Printf(unicastHeader)
		_printIps(unicasts)
	}

	/* print multicast addresses */
	if len(multicasts) > 0 {
		fmt.Printf(multicastHeader)
		_printIps(multicasts)
	}
}

/* print peer addresses in device table */
func printPeers(device *deviceInfo) {
	macPeersHeader := "  MAC Peers:\n"
	ipPeersHeader := "  IP Peers:\n"

	if len(device.macPeers) > 0 {
		var macs []*ipInfo
		for _, info := range device.macPeers {
			macs = append(macs, info)
		}
		fmt.Printf(macPeersHeader)
		_printIps(macs)
	}

	if len(device.ipPeers) > 0 {
		var ips []*ipInfo
		for _, info := range device.ipPeers {
			ips = append(ips, info)
		}
		fmt.Printf(ipPeersHeader)
		_printIps(ips)
	}
}

/* print device table periodically */
func printDevices() {
	devicesFmt := "===================================" +
		"===================================\n" +
		"Devices: %-39d (pkts: %d)\n" +
		"===================================" +
		"===================================\n"
	macFmt := "MAC: %-43s (age: %.f, pkts: %d)\n"
	for {
		/* start with devices header */
		fmt.Printf(devicesFmt, len(devices), packets)

		/* lock devices */
		devicesLock.Lock()

		for mac, device := range devices {
			/* print MAC address */
			fmt.Printf(macFmt, mac, device.getAge(),
				device.packets)
			/* print properties and ips */
			printProperties(device)
			printIps(device)
			printPeers(device)
			fmt.Println()
		}

		/* unlock devices */
		devicesLock.Unlock()

		/* wait 5 seconds before printing */
		time.Sleep(5 * time.Second)
	}
}

/*
 ************
 *** MAIN ***
 ************
 */

/* listen on network interface and parse packets */
func listen() {
	/* convert pcap parameters from command line arguments */
	_pcapTimeout := time.Duration(pcapTimeout) * time.Second
	_pcapSnaplen := int32(pcapSnaplen)

	/* open device */
	pcapHandle, pcapErr = pcap.OpenLive(pcapDevice, _pcapSnaplen,
		pcapPromisc, _pcapTimeout)
	if pcapErr != nil {
		log.Fatal(pcapErr)
	}
	defer pcapHandle.Close()

	/* print device table periodically */
	go printDevices()

	/* Use the handle as a packet source to process all packets */
	packetSource := gopacket.NewPacketSource(pcapHandle,
		pcapHandle.LinkType())
	for packet := range packetSource.Packets() {
		/* lock devices */
		devicesLock.Lock()

		/* parse packet */
		parseSrcMac(packet)
		parsePeers(packet)
		parseVlan(packet)
		parseVxlan(packet)
		parseArp(packet)
		parseNdp(packet)
		parseIgmp(packet)
		parseMld(packet)
		parseDhcp(packet)
		parseStp(packet)
		parsePlc(packet)
		updateStatistics(packet)

		/* unlock devices */
		devicesLock.Unlock()
	}
}

/* parse command line arguments */
func parseCommandLine() {
	/* define command line arguments */
	flag.StringVar(&pcapDevice, "i", pcapDevice,
		"the interface to listen on")
	flag.BoolVar(&pcapPromisc, "pcap-promisc", pcapPromisc,
		"Set pcap promiscuous parameter")
	flag.IntVar(&pcapTimeout, "pcap-timeout", pcapTimeout,
		"Set pcap timeout parameter in seconds")
	flag.IntVar(&pcapSnaplen, "pcap-snaplen", pcapSnaplen,
		"Set pcap snapshot length parameter in bytes")
	flag.BoolVar(&debugMode, "debug", debugMode, "debugging mode")
	flag.BoolVar(&withPeers, "peers", withPeers, "show peers")

	/* parse and overwrite default values of settings */
	flag.Parse()

	/* output settings */
	debug(fmt.Sprintf("Pcap Listen Device: %s", pcapDevice))
	debug(fmt.Sprintf("Pcap Promiscuous: %t", pcapPromisc))
	debug(fmt.Sprintf("Pcap Timeout: %d", pcapTimeout))
	debug(fmt.Sprintf("Pcap Snaplen: %d", pcapSnaplen))
	debug(fmt.Sprintf("Debugging Output: %t", debugMode))
	debug(fmt.Sprintf("Peers Output: %t", withPeers))
}

/* main function */
func main() {
	parseCommandLine()
	listen()
}
