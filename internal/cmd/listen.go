package cmd

import (
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// listen listens on the network interface and parses packets
func listen() {
	// convert pcap parameters from command line arguments
	_pcapTimeout := time.Duration(pcapTimeout) * time.Second
	_pcapSnaplen := int32(pcapSnaplen)

	// open device
	pcapHandle, pcapErr = pcap.OpenLive(pcapDevice, _pcapSnaplen,
		pcapPromisc, _pcapTimeout)
	if pcapErr != nil {
		log.Fatal(pcapErr)
	}
	defer pcapHandle.Close()

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(pcapHandle,
		pcapHandle.LinkType())
	for packet := range packetSource.Packets() {
		// lock devices
		devicesLock.Lock()

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
		devicesLock.Unlock()
	}
}
