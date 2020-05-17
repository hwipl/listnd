package cmd

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"github.com/hwipl/listnd/internal/pkt"
)

var (
	pcapHandle *pcap.Handle
	pcapErr    error
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
	var startText string
	// convert pcap parameters from command line arguments
	_pcapTimeout := time.Duration(pcapTimeout) * time.Second
	_pcapSnaplen := int32(pcapSnaplen)

	if pcapFile == "" {
		// set interface
		if pcapDevice == "" {
			getFirstPcapInterface()
		}
		// open device
		pcapHandle, pcapErr = pcap.OpenLive(pcapDevice, _pcapSnaplen,
			pcapPromisc, _pcapTimeout)
		startText = fmt.Sprintf("Listening on interface %s:\n",
			pcapDevice)
	} else {
		// open pcap file
		pcapHandle, pcapErr = pcap.OpenOffline(pcapFile)
		startText = fmt.Sprintf("Reading packets from file %s:\n",
			pcapFile)
	}
	defer pcapHandle.Close()
	if pcapErr != nil {
		log.Fatal(pcapErr)
	}

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(pcapHandle,
		pcapHandle.LinkType())
	log.Printf(startText)
	for packet := range packetSource.Packets() {
		pkt.Parse(packet)
	}
}
