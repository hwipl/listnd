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

/* struct for ip addresses of devices on the network */
type ip_info struct {
	ip gopacket.Endpoint
	packets int
}

/* struct for devices found on the network */
type device_info struct {
	mac gopacket.Endpoint
	router bool
	prefixes []layers.ICMPv6Option
	packets int
	ips map[gopacket.Endpoint]*ip_info
}

/* variable definitions */
var (
	/* network device map and debugging mode */
	devices = make(map[gopacket.Endpoint]*device_info)
	debug_mode	bool = false

	/* pcap settings */
	pcap_promisc	bool = true
	pcap_device	string = "eth0"
	pcap_snaplen	int32  = 1024
	pcap_timeout	time.Duration = 1 * time.Second
	pcap_handle	*pcap.Handle
	pcap_err	error
)

/* debug output */
func debug(text string) {
	if debug_mode {
		fmt.Println(text)
	}
}

/* parse MAC and IP addresses in packet */
// TODO: change this to macs only?
func parse_macs_and_ips(packet gopacket.Packet) {
	if link := packet.LinkLayer(); link != nil {
		/* extract MAC addresses */
		link_src, link_dst := link.LinkFlow().Endpoints()
		if net := packet.NetworkLayer(); net != nil {
			/* extract IP addresses */
			net_src, net_dst := net.NetworkFlow().Endpoints()

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
	}
}

/* parse ARP packets */
func parse_arp(packet gopacket.Packet) {
	arpLayer := packet.Layer(layers.LayerTypeARP)
	if arpLayer != nil {
		debug("ARP Request or Reply")
		arp, _ := arpLayer.(*layers.ARP)
		// TODO: use other info like arp.Operation, arp.DstHwAddress,
		// or arp.DstProtAddress?
		/* get addresses */
		link_src := layers.NewMACEndpoint(arp.SourceHwAddress)
		net_src := layers.NewIPEndpoint(arp.SourceProtAddress)

		/* add to table */
		add_table_entry(link_src, net_src)
	}
}

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

/* helper for adding a table entry */
func add_table_entry(link_addr, net_addr gopacket.Endpoint) {
	/* create table entries if necessary */
	if devices[link_addr] == nil {
		debug("Adding new entry")
		device := device_info{}
		device.mac = link_addr
		device.ips = make(map[gopacket.Endpoint]*ip_info)
		devices[link_addr] = &device
	}
	/* init net address counter */
	if devices[link_addr].ips[net_addr] == nil {
		debug("Adding new ip to an entry")
		ip := ip_info{}
		ip.ip = net_addr
		devices[link_addr].ips[net_addr] = &ip
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
		add_table_entry(link_src, net_src)

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
		add_table_entry(link_src, target_ip)

		return
	}

	rsolLayer := packet.Layer(layers.LayerTypeICMPv6RouterSolicitation)
	if rsolLayer != nil {
		debug("Router Solicitation")
		/* router solicitation, get src mac and src ip */
		link_src, _ := get_macs(packet)
		net_src, _ := get_ips(packet)

		/* add to table */
		add_table_entry(link_src, net_src)

		return
	}

	radvLayer := packet.Layer(layers.LayerTypeICMPv6RouterAdvertisement)
	if radvLayer != nil {
		debug("Router Advertisement")
		/* router advertisement, get src mac and src ip */
		link_src, _ := get_macs(packet)
		net_src, _ := get_ips(packet)

		/* add to table */
		add_table_entry(link_src, net_src)

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

/* print device table periodically */
func print_devices() {
	header := "========================= Devices ========================="
	mac_fmt := "MAC: %s\n"
	ip_fmt := "    IP: %-40s (%d pkts)\n"
	for {
		/* start with header */
		fmt.Println(header)
		for mac, device := range devices {
			/* print MAC address */
			fmt.Printf(mac_fmt, mac)
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

/* listen on network interface and parse packets */
func listen() {
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
		parse_arp(packet)
		parse_ndp(packet)
		parse_macs_and_ips(packet)
	}
}

/* parse command line arguments */
func parse_command_line() {
	/* define command line arguments */
	// TODO: add other settings as command line arguments?
	flag.StringVar(&pcap_device, "i", pcap_device,
		       "the interface to listen on")
	flag.BoolVar(&pcap_promisc, "promisc", pcap_promisc,
		     "promiscuous mode")
	flag.BoolVar(&debug_mode, "debug", debug_mode, "debugging mode")

	/* parse and overwrite default values of settings */
	flag.Parse()

	/* output settings */
	debug(fmt.Sprintf("Pcap Listen Device: %s", pcap_device))
	debug(fmt.Sprintf("Pcap Promiscuous: %t", pcap_promisc))
	debug(fmt.Sprintf("Debugging Output: %t", debug_mode))
}

/* main function */
func main() {
	parse_command_line()
	listen()
}
