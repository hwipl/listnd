package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
	"log"
	"time"
)

var (
	device		string = "eth0"
	snapshot_len	int32  = 1024
	promiscuous	bool = true
	err		error
	timeout		time.Duration = 1 * time.Second
	handle		*pcap.Handle
	// TODO: make a struct for network device/host infos and use it?
	macs = make(map[gopacket.Endpoint]map[gopacket.Endpoint]int)
)

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
			if macs[link_src] != nil &&
			   macs[link_src][net_src] != 0 {
				macs[link_src][net_src] += 1
			}
			if macs[link_dst] != nil &&
			   macs[link_dst][net_dst] != 0 {
				macs[link_dst][net_dst] += 1
			}
		}
	}
}

/* parse ARP packets */
func parse_arp(packet gopacket.Packet) {
	arpLayer := packet.Layer(layers.LayerTypeARP)
	if arpLayer != nil {
		arp, _ := arpLayer.(*layers.ARP)
		// TODO: use other info like arp.Operation, arp.DstHwAddress,
		// or arp.DstProtAddress?
		/* get addresses */
		link_src := layers.NewMACEndpoint(arp.SourceHwAddress)
		net_src := layers.NewIPEndpoint(arp.SourceProtAddress)

		/* create table entries if necessary */
		if macs[link_src] == nil {
			macs[link_src] = make(map[gopacket.Endpoint]int)
		}

		/* increase packet counter */
		macs[link_src][net_src] += 1
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

/* parse neighbor discovery protocol packets */
func parse_ndp(packet gopacket.Packet) {
	nsolLayer := packet.Layer(layers.LayerTypeICMPv6NeighborSolicitation)
	if nsolLayer != nil {
		/* neighbor solicitation, get src mac and src ip */
		link_src, _ := get_macs(packet)
		net_src, _ := get_ips(packet)

		/* create table entries if necessary */
		if macs[link_src] == nil {
			macs[link_src] = make(map[gopacket.Endpoint]int)
		}

		/* increase packet counter */
		macs[link_src][net_src] += 1

		return
	}

	nadvLayer := packet.Layer(layers.LayerTypeICMPv6NeighborAdvertisement)
	if nadvLayer != nil {
		/* neighbor advertisement, get src mac and target ip */
		adv, _ := nadvLayer.(*layers.ICMPv6NeighborAdvertisement)
		target_ip := layers.NewIPEndpoint(adv.TargetAddress)
		link_src, _ := get_macs(packet)

		/* create table entries if necessary */
		if macs[link_src] == nil {
			macs[link_src] = make(map[gopacket.Endpoint]int)
		}

		/* increase packet counter */
		macs[link_src][target_ip] += 1

		return
	}

	rsolLayer := packet.Layer(layers.LayerTypeICMPv6RouterSolicitation)
	if rsolLayer != nil {
		/* router solicitation, get src mac and src ip */
		link_src, _ := get_macs(packet)
		net_src, _ := get_ips(packet)

		/* create table entries if necessary */
		if macs[link_src] == nil {
			macs[link_src] = make(map[gopacket.Endpoint]int)
		}

		/* increase packet counter */
		macs[link_src][net_src] += 1

		return
	}

	radvLayer := packet.Layer(layers.LayerTypeICMPv6RouterAdvertisement)
	if radvLayer != nil {
		/* router advertisement, get src mac and src ip */
		link_src, _ := get_macs(packet)
		net_src, _ := get_ips(packet)

		/* create table entries if necessary */
		if macs[link_src] == nil {
			macs[link_src] = make(map[gopacket.Endpoint]int)
		}

		/* increase packet counter */
		macs[link_src][net_src] += 1

		return
	}
}

/* print device table periodically */
func print_devices() {
	for {
		fmt.Println("================ Devices ================")
		for mac, ips := range macs {
			fmt.Println("MAC:", mac)
			for ip, count := range ips {
				fmt.Println("	IP: ", ip, " (", count, "pkts)")
			}
			fmt.Println()
		}
		time.Sleep(5 * time.Second)
	}
}

/* listen on network interface and parse packets */
func listen() {
	/* open device */
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	/* print device table periodically */
	go print_devices()

	/* Use the handle as a packet source to process all packets */
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
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
	flag.StringVar(&device, "i", device, "the interface to listen on")
	flag.BoolVar(&promiscuous, "promisc", promiscuous, "promiscuous mode")

	/* parse and overwrite default values of settings */
	flag.Parse()

	/* output settings */
	fmt.Println("Device: ", device)
	fmt.Println("Promiscuous: ", promiscuous)
}

/* main function */
func main() {
	parse_command_line()
	listen()
}
