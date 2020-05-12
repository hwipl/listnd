package cmd

import (
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"github.com/hwipl/listnd/internal/pkt"
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
		pkt.Parse(packet)
	}
}
