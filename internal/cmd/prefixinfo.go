package cmd

import "github.com/google/gopacket/layers"

// prefixInfo stores a router's prefix information
type prefixInfo struct {
	timeInfo
	prefix layers.ICMPv6Option
}
