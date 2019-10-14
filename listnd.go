package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

/* variable definitions */
var (
	/* network device map and debugging mode */
	devices        = make(deviceMap)
	debugMode bool = false

	/* pcap settings */
	pcapPromisc bool   = true
	pcapDevice  string = "eth0"
	pcapSnaplen int    = 1024
	pcapTimeout int    = 1
	pcapHandle  *pcap.Handle
	pcapErr     error
)

/*
 ********************
 *** DEVICE TABLE ***
 ********************
 */

/* struct for vlan information */
type vlanInfo struct {
	vlan    uint16
	packets int
}

/* struct for ip addresses of devices on the network */
type ipInfo struct {
	ip      gopacket.Endpoint
	packets int
}

/* struct for devices found on the network */
type deviceInfo struct {
	mac       gopacket.Endpoint
	vlans     map[uint16]*vlanInfo
	powerline bool
	bridge    bool
	dhcp      bool
	router    bool
	prefixes  []layers.ICMPv6Option
	packets   int
	ips       map[gopacket.Endpoint]*ipInfo
}

/* device table definition */
type deviceMap map[gopacket.Endpoint]*deviceInfo

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

/* add a device to the device table */
func (d deviceMap) add(linkAddr gopacket.Endpoint) {
	/* create table entries if necessary */
	if d[linkAddr] == nil {
		debug("Adding new entry")
		device := deviceInfo{}
		device.mac = linkAddr
		device.vlans = make(map[uint16]*vlanInfo)
		device.ips = make(map[gopacket.Endpoint]*ipInfo)
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

/* parse the source MAC address and add it to device table */
func parseSrcMac(packet gopacket.Packet) {
	linkSrc, _ := getMacs(packet)
	devices.add(linkSrc)
}

/* parse MAC and IP addresses in packet */
func parseMacsAndIps(packet gopacket.Packet) {
	/* get addresses */
	linkSrc, linkDst := getMacs(packet)
	netSrc, netDst := getIps(packet)

	/* increase packet counters */
	if devices[linkSrc] != nil &&
		devices[linkSrc].ips[netSrc] != nil {
		devices[linkSrc].ips[netSrc].packets++
	}
	if devices[linkDst] != nil &&
		devices[linkDst].ips[netDst] != nil {
		devices[linkDst].ips[netDst].packets++
	}
}

/* parse VLAN tags */
func parseVlan(packet gopacket.Packet) {
	vlanLayer := packet.Layer(layers.LayerTypeDot1Q)
	if vlanLayer != nil {
		debug("VLAN Tag")
		vlan, _ := vlanLayer.(*layers.Dot1Q)
		linkSrc, _ := getMacs(packet)
		devices[linkSrc].addVlan(vlan.VLANIdentifier)
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
		devices[linkSrc].router = true

		/* flush prefixes and refill with advertised ones */
		adv, _ := radvLayer.(*layers.ICMPv6RouterAdvertisement)
		devices[linkSrc].prefixes = nil
		for i := range adv.Options {
			if adv.Options[i].Type == layers.ICMPv6OptPrefixInfo {
				devices[linkSrc].prefixes = append(
					devices[linkSrc].prefixes,
					adv.Options[i])
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

	/* igmp v1 or v2 */
	if igmp, ok := igmpLayer.(*layers.IGMPv1or2); ok {
		/* parse message type */
		switch igmp.Type {
		case layers.IGMPMembershipQuery:
			debug("IGMPv1or2 Membership Query")
			/* queries are sent by routers, mark as router */
			devices[linkSrc].router = true
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
			devices[linkSrc].router = true
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
		devices[linkSrc].router = true
		return
	}

	dlv1 := packet.Layer(layers.LayerTypeMLDv1MulticastListenerDone)
	if dlv1 != nil {
		debug("MLDv1 Done Message")
		/* parse and remove multicast address */
		done, _ := dlv1.(*layers.MLDv1MulticastListenerDoneMessage)
		linkSrc, _ := getMacs(packet)
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
		devices[linkSrc].router = true
		return
	}

	rlv2 := packet.Layer(layers.LayerTypeMLDv2MulticastListenerReport)
	if rlv2 != nil {
		debug("MLDv2 Report Message")
		report, _ := rlv2.(*layers.MLDv2MulticastListenerReportMessage)
		linkSrc, _ := getMacs(packet)

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
			devices[linkSrc].dhcp = true
		}
	}

	/* DHCP v6 */
	dhcpv6Layer := packet.Layer(layers.LayerTypeDHCPv6)
	if dhcpv6Layer != nil {
		dhcp, _ := dhcpv6Layer.(*layers.DHCPv6)
		linkSrc, _ := getMacs(packet)

		/* parse message type to determine if server or client */
		switch dhcp.MsgType {
		case layers.DHCPv6MsgTypeSolicit:
			debug("DHCPv6 Solicit")
		case layers.DHCPv6MsgTypeAdverstise:
			debug("DHCPv6 Advertise")
		case layers.DHCPv6MsgTypeRequest:
			debug("DHCPv6 Request")
			devices[linkSrc].dhcp = true
		case layers.DHCPv6MsgTypeConfirm:
			debug("DHCPv6 Confirm")
		case layers.DHCPv6MsgTypeRenew:
			debug("DHCPv6 Renew")
		case layers.DHCPv6MsgTypeRebind:
			debug("DHCPv6 Rebind")
		case layers.DHCPv6MsgTypeReply:
			debug("DHCPv6 Reply")
			devices[linkSrc].dhcp = true
		case layers.DHCPv6MsgTypeRelease:
			debug("DHCPv6 Release")
		case layers.DHCPv6MsgTypeDecline:
			debug("DHCPv6 Decline")
		case layers.DHCPv6MsgTypeReconfigure:
			debug("DHCPv6 Reconfigure")
			devices[linkSrc].dhcp = true
		case layers.DHCPv6MsgTypeInformationRequest:
			debug("DHCPv6 Information Request")
		case layers.DHCPv6MsgTypeRelayForward:
			debug("DHCPv6 Relay Forward")
		case layers.DHCPv6MsgTypeRelayReply:
			debug("DHCPv6 Relay Reply")
			devices[linkSrc].dhcp = true
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
		devices[linkSrc].bridge = true
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
			devices[linkSrc].powerline = true
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
	routerHeader := "    Router: true\n"
	prefixFmt := "        Prefix: %v/%v\n"

	fmt.Printf(routerHeader)
	for _, prefix := range device.prefixes {
		pLen := uint8(prefix.Data[0])
		p := net.IP(prefix.Data[14:])
		fmt.Printf(prefixFmt, p, pLen)
	}
}

/* print dhcp information in device table */
func printDhcp(device *deviceInfo) {
	dhcpHeader := "    DHCP: server\n"
	fmt.Printf(dhcpHeader)
}

/* print bridge information in device table */
func printBridge(device *deviceInfo) {
	bridgeHeader := "    Bridge: true\n"
	fmt.Printf(bridgeHeader)
}

/* print powerline information in device table */
func printPowerline(device *deviceInfo) {
	powerlineHeader := "    Powerline: true\n"
	fmt.Printf(powerlineHeader)
}

/* print device table periodically */
func printDevices() {
	devicesFmt := "==============================" +
		"==============================\n" +
		"Devices: %d\n" +
		"==============================" +
		"==============================\n"
	macFmt := "MAC: %s\n"
	vlanFmt := "    VLAN: %d\n"
	ipFmt := "    IP: %-40s (%d pkts)\n"
	for {
		/* start with devices header */
		fmt.Printf(devicesFmt, len(devices))
		for mac, device := range devices {
			/* print MAC address */
			fmt.Printf(macFmt, mac)
			if device.bridge {
				/* print bridge info */
				printBridge(device)
			}
			if device.dhcp {
				/* print dhcp info */
				printDhcp(device)
			}
			if device.router {
				/* print router info */
				printRouter(device)
			}
			if device.powerline {
				/* print powerline info */
				printPowerline(device)
			}
			for _, vlan := range device.vlans {
				/* print VLAN info */
				fmt.Printf(vlanFmt, vlan.vlan)
			}
			for ip, info := range device.ips {
				/* print IP address info */
				fmt.Printf(ipFmt, ip, info.packets)
			}
			fmt.Println()
		}
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
		/* parse packet */
		parseSrcMac(packet)
		parseVlan(packet)
		parseArp(packet)
		parseNdp(packet)
		parseIgmp(packet)
		parseMld(packet)
		parseDhcp(packet)
		parseStp(packet)
		parsePlc(packet)
		parseMacsAndIps(packet)
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

	/* parse and overwrite default values of settings */
	flag.Parse()

	/* output settings */
	debug(fmt.Sprintf("Pcap Listen Device: %s", pcapDevice))
	debug(fmt.Sprintf("Pcap Promiscuous: %t", pcapPromisc))
	debug(fmt.Sprintf("Pcap Timeout: %d", pcapTimeout))
	debug(fmt.Sprintf("Pcap Snaplen: %d", pcapSnaplen))
	debug(fmt.Sprintf("Debugging Output: %t", debugMode))
}

/* main function */
func main() {
	parseCommandLine()
	listen()
}
