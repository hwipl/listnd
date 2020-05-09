package cmd

import "github.com/google/gopacket"

// AddrInfo stores an ip or mac address of a device on the network
type AddrInfo struct {
	timeInfo
	Addr    gopacket.Endpoint
	Packets int
}
