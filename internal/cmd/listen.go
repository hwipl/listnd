package cmd

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"github.com/hwipl/listnd/internal/pkt"
)

// getFirstPcapInterface sets the first network interface found by pcap
func getFirstPcapInterface() {
	ifs, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	if len(ifs) > 0 {
		pcapDevice = ifs[0].Name
		return
	}
	log.Fatal("No network interface found")
}

// listen listens on the network interface and parses packets
func listen() {
	// convert pcap parameters from command line arguments
	_pcapTimeout := time.Duration(pcapTimeout) * time.Second
	_pcapSnaplen := int32(pcapSnaplen)

	// set interface
	if pcapDevice == "" {
		getFirstPcapInterface()
	}
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
	startText := fmt.Sprintf("Listening on interface %s:\n", pcapDevice)
	log.Printf(startText)
	for packet := range packetSource.Packets() {
		pkt.Parse(packet)
	}
}
