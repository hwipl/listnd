package cmd

import (
	"github.com/google/gopacket"
)

// deviceInfo is a device found on the network
type deviceInfo struct {
	timeInfo
	mac       gopacket.Endpoint
	vlans     vnetMap
	vxlans    vnetMap
	geneves   vnetMap
	powerline propInfo
	bridge    propInfo
	dhcp      propInfo
	router    routerInfo
	packets   int
	ucasts    AddrMap
	mcasts    AddrMap
	macPeers  AddrMap
	ipPeers   AddrMap
}
