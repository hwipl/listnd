package cmd

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// AddrInfo stores an ip or mac address of a device on the network
type AddrInfo struct {
	timeInfo
	Addr    gopacket.Endpoint
	Packets int
}

// String converts address info to a string
func (a *AddrInfo) String() string {
	var aFmt string
	if a.Addr.EndpointType() == layers.EndpointMAC {
		aFmt = "MAC: %-39s (age: %.f, pkts: %d)"
	} else {
		aFmt = "IP: %-40s (age: %.f, pkts: %d)"
	}

	return fmt.Sprintf(aFmt, a.Addr, a.getAge(), a.Packets)
}
