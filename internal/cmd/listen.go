package cmd

import (
	"github.com/gopacket/gopacket"

	"github.com/hwipl/listnd/internal/pkt"
	"github.com/hwipl/packet-go/pkg/pcap"
)

type handler struct{}

func (h *handler) HandlePacket(packet gopacket.Packet) {
	pkt.Parse(packet)
}

// listen captures packets on the network interface and parses them
func listen() {
	// create handler
	var handler handler

	// create listener
	listener := pcap.Listener{
		PacketHandler: &handler,
		File:          pcapFile,
		Device:        pcapDevice,
		Promisc:       pcapPromisc,
		Snaplen:       pcapSnaplen,
		Filter:        pcapFilter,
	}

	// start listen loop
	listener.Prepare()
	listener.Loop()
}
