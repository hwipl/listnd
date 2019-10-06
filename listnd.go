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

func print_layers(packet gopacket.Packet) {
	fmt.Println("All packet layers:")
	for _, layer := range packet.Layers() {
		fmt.Println("- ", layer.LayerType())
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
		parse_macs_and_ips(packet)
		parse_arp(packet)
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
