package cmd

import "github.com/google/gopacket"

// ipInfo stores an ip address of a device on the network
type ipInfo struct {
	timeInfo
	ip      gopacket.Endpoint
	packets int
}
