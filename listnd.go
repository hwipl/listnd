package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
	"log"
	"time"
	"net"
)

/* variable definitions */
var (
	/* network device map and debugging mode */
	devices		= make(device_map)
	debug_mode	bool = false

	/* pcap settings */
	pcap_promisc	bool = true
	pcap_device	string = "eth0"
	pcap_snaplen	int = 1024
	pcap_timeout	int = 1
	pcap_handle	*pcap.Handle
	pcap_err	error
)

/*
 ********************
 *** DEVICE TABLE ***
 ********************
 */

/* struct for ip addresses of devices on the network */
type ip_info struct {
	ip		gopacket.Endpoint
	packets		int
}

/* struct for devices found on the network */
type device_info struct {
	mac		gopacket.Endpoint
	bridge		bool
	dhcp		bool
	router		bool
	prefixes	[]layers.ICMPv6Option
	packets		int
	ips		map[gopacket.Endpoint]*ip_info
}

/* device table definition */
type device_map map[gopacket.Endpoint]*device_info

/* add an ip address to a device */
func (d *device_info) add_ip(net_addr gopacket.Endpoint) {
	/* make sure address is valid */
	if !endpoint_is_valid_ip(net_addr) {
		return
	}
	/* init net address counter */
	if d.ips[net_addr] == nil {
		debug("Adding new ip to an entry")
		ip := ip_info{}
		ip.ip = net_addr
		d.ips[net_addr] = &ip
	}
}

/* add a device to the device table */
func (d device_map) add(link_addr gopacket.Endpoint) {
	/* create table entries if necessary */
	if d[link_addr] == nil {
		debug("Adding new entry")
		device := device_info{}
		device.mac = link_addr
		device.ips = make(map[gopacket.Endpoint]*ip_info)
		d[link_addr] = &device
	}
}

/* add a device table entry with mac and ip address*/
func (d device_map) add_mac_ip(link_addr, net_addr gopacket.Endpoint) {
	d.add(link_addr)
	d[link_addr].add_ip(net_addr)
}

/* check if IP address in endpoint is valid */
var addr_zero gopacket.Endpoint
var addr_unspecv4 = layers.NewIPEndpoint(net.ParseIP("0.0.0.0"))
var addr_unspecv6 = layers.NewIPEndpoint(net.ParseIP("::"))

func endpoint_is_valid_ip(e gopacket.Endpoint) (bool) {
	if e == addr_zero || e == addr_unspecv4 || e == addr_unspecv6 {
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
func get_macs(packet gopacket.Packet) (gopacket.Endpoint, gopacket.Endpoint) {
	var link_src, link_dst gopacket.Endpoint

	if link := packet.LinkLayer(); link != nil {
		/* extract MAC addresses */
		link_src, link_dst = link.LinkFlow().Endpoints()
	}

	return link_src, link_dst
}

/* helper for getting src and dst ip addresses of packet */
func get_ips(packet gopacket.Packet) (gopacket.Endpoint, gopacket.Endpoint) {
	var net_src, net_dst gopacket.Endpoint

	if net := packet.NetworkLayer(); net != nil {
		/* extract IP addresses */
		net_src, net_dst = net.NetworkFlow().Endpoints()
	}

	return net_src, net_dst
}

/* parse the source MAC address and add it to device table */
func parse_src_mac(packet gopacket.Packet) {
	link_src, _ := get_macs(packet)
	devices.add(link_src)
}

/* parse MAC and IP addresses in packet */
func parse_macs_and_ips(packet gopacket.Packet) {
	/* get addresses */
	link_src, link_dst := get_macs(packet)
	net_src, net_dst := get_ips(packet)

	/* increase packet counters */
	if devices[link_src] != nil &&
	   devices[link_src].ips[net_src] != nil {
		   devices[link_src].ips[net_src].packets += 1
	}
	if devices[link_dst] != nil &&
	   devices[link_dst].ips[net_dst] != nil {
		   devices[link_dst].ips[net_dst].packets += 1
	}
}

/* parse ARP packets */
func parse_arp(packet gopacket.Packet) {
	arpLayer := packet.Layer(layers.LayerTypeARP)
	if arpLayer != nil {
		debug("ARP Request or Reply")
		arp, _ := arpLayer.(*layers.ARP)
		/* get addresses */
		link_src := layers.NewMACEndpoint(arp.SourceHwAddress)
		net_src := layers.NewIPEndpoint(arp.SourceProtAddress)

		/* add to table */
		devices.add_mac_ip(link_src, net_src)
	}
}

/* parse neighbor discovery protocol packets */
func parse_ndp(packet gopacket.Packet) {
	nsolLayer := packet.Layer(layers.LayerTypeICMPv6NeighborSolicitation)
	if nsolLayer != nil {
		debug("Neighbor Solicitation")
		/* neighbor solicitation, get src mac and src ip */
		link_src, _ := get_macs(packet)
		net_src, _ := get_ips(packet)

		/* add to table */
		devices.add_mac_ip(link_src, net_src)

		return
	}

	nadvLayer := packet.Layer(layers.LayerTypeICMPv6NeighborAdvertisement)
	if nadvLayer != nil {
		debug("Neighbor Advertisement")
		/* neighbor advertisement, get src mac and target ip */
		adv, _ := nadvLayer.(*layers.ICMPv6NeighborAdvertisement)
		target_ip := layers.NewIPEndpoint(adv.TargetAddress)
		link_src, _ := get_macs(packet)

		/* add to table */
		devices.add_mac_ip(link_src, target_ip)

		return
	}

	rsolLayer := packet.Layer(layers.LayerTypeICMPv6RouterSolicitation)
	if rsolLayer != nil {
		debug("Router Solicitation")
		/* router solicitation, get src mac and src ip */
		link_src, _ := get_macs(packet)
		net_src, _ := get_ips(packet)

		/* add to table */
		devices.add_mac_ip(link_src, net_src)

		return
	}

	radvLayer := packet.Layer(layers.LayerTypeICMPv6RouterAdvertisement)
	if radvLayer != nil {
		debug("Router Advertisement")
		/* router advertisement, get src mac and src ip */
		link_src, _ := get_macs(packet)
		net_src, _ := get_ips(packet)

		/* add to table */
		devices.add_mac_ip(link_src, net_src)

		/* mark device as a router */
		devices[link_src].router = true

		/* flush prefixes and refill with advertised ones */
		adv, _ := radvLayer.(*layers.ICMPv6RouterAdvertisement)
		devices[link_src].prefixes = nil
		for i := range adv.Options {
			if adv.Options[i].Type == layers.ICMPv6OptPrefixInfo {
				devices[link_src].prefixes = append(
					devices[link_src].prefixes,
					adv.Options[i])
			}
		}
		return
	}
}

/* parse dhcp packets */
func parse_dhcp(packet gopacket.Packet) {
	dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
	if dhcpLayer != nil {
		debug("DHCP Request or Reply")
		dhcp, _ := dhcpLayer.(*layers.DHCPv4)
		link_src, _ := get_macs(packet)

		/* add device */
		devices.add(link_src)
		if dhcp.Operation == layers.DHCPOpReply {
			/* mark this device as dhcp server */
			devices[link_src].dhcp = true
		}
	}
}

/* parse stp packets */
func parse_stp(packet gopacket.Packet) {
	stpLayer := packet.Layer(layers.LayerTypeSTP)
	if stpLayer != nil {
		debug("STP packet")
		link_src, _ := get_macs(packet)

		/* add device and mark this device as a bridge */
		devices.add(link_src)
		devices[link_src].bridge = true
	}
}

/*
 **********************
 *** CONSOLE OUTPUT ***
 **********************
 */

/* debug output */
func debug(text string) {
	if debug_mode {
		fmt.Println(text)
	}
}

/* print router information in device table */
func print_router(device *device_info) {
	router_header := "    Router:\n"
	prefix_fmt := "        Prefix: %v/%v\n"

	fmt.Printf(router_header)
	for _, prefix := range device.prefixes {
		p_len := uint8(prefix.Data[0])
		p := net.IP(prefix.Data[14:])
		fmt.Printf(prefix_fmt, p, p_len)
	}
}

/* print dhcp information in device table */
func print_dhcp(device *device_info) {
	dhcp_header := "    DHCP: server\n"
	fmt.Printf(dhcp_header)
}

/* print bridge information in device table */
func print_bridge(device *device_info) {
	bridge_header := "    Bridge: true\n"
	fmt.Printf(bridge_header)
}

/* print device table periodically */
func print_devices() {
	devices_fmt :=
		"==============================" +
		"==============================\n" +
		"Devices: %d\n" +
		"==============================" +
		"==============================\n"
	mac_fmt := "MAC: %s\n"
	ip_fmt := "    IP: %-40s (%d pkts)\n"
	for {
		/* start with devices header */
		fmt.Printf(devices_fmt, len(devices))
		for mac, device := range devices {
			/* print MAC address */
			fmt.Printf(mac_fmt, mac)
			if device.bridge {
				/* print bridge info */
				print_bridge(device)
			}
			if device.dhcp {
				/* print dhcp info */
				print_dhcp(device)
			}
			if device.router {
				/* print router info */
				print_router(device)
			}
			for ip, info := range device.ips {
				/* print IP address info */
				fmt.Printf(ip_fmt, ip, info.packets)
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
	pcap_timeout := time.Duration(pcap_timeout) * time.Second
	pcap_snaplen := int32(pcap_snaplen)

	/* open device */
	pcap_handle, pcap_err = pcap.OpenLive(pcap_device, pcap_snaplen,
					      pcap_promisc, pcap_timeout)
	if pcap_err != nil {
		log.Fatal(pcap_err)
	}
	defer pcap_handle.Close()

	/* print device table periodically */
	go print_devices()

	/* Use the handle as a packet source to process all packets */
	packetSource := gopacket.NewPacketSource(pcap_handle,
						 pcap_handle.LinkType())
	for packet := range packetSource.Packets() {
		/* parse packet */
		parse_src_mac(packet)
		parse_arp(packet)
		parse_ndp(packet)
		parse_dhcp(packet)
		parse_stp(packet)
		parse_macs_and_ips(packet)
	}
}

/* parse command line arguments */
func parse_command_line() {
	/* define command line arguments */
	flag.StringVar(&pcap_device, "i", pcap_device,
		       "the interface to listen on")
	flag.BoolVar(&pcap_promisc, "pcap-promisc", pcap_promisc,
		     "Set pcap promiscuous parameter")
	flag.IntVar(&pcap_timeout, "pcap-timeout", pcap_timeout,
		    "Set pcap timeout parameter in seconds")
	flag.IntVar(&pcap_snaplen, "pcap-snaplen", pcap_snaplen,
		    "Set pcap snapshot length parameter in bytes")
	flag.BoolVar(&debug_mode, "debug", debug_mode, "debugging mode")

	/* parse and overwrite default values of settings */
	flag.Parse()

	/* output settings */
	debug(fmt.Sprintf("Pcap Listen Device: %s", pcap_device))
	debug(fmt.Sprintf("Pcap Promiscuous: %t", pcap_promisc))
	debug(fmt.Sprintf("Pcap Timeout: %d", pcap_timeout))
	debug(fmt.Sprintf("Pcap Snaplen: %d", pcap_snaplen))
	debug(fmt.Sprintf("Debugging Output: %t", debug_mode))
}

/* main function */
func main() {
	parse_command_line()
	listen()
}
