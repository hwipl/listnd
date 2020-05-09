package cmd

import (
	"github.com/google/gopacket"
)

// deviceInfo is a device found on the network
type deviceInfo struct {
	timeInfo
	mac       gopacket.Endpoint
	vlans     map[uint16]*vnetInfo
	vxlans    vnetMap
	geneves   vnetMap
	powerline powerlineInfo
	bridge    bridgeInfo
	dhcp      dhcpInfo
	router    routerInfo
	packets   int
	ips       AddrMap
	macPeers  AddrMap
	ipPeers   AddrMap
}

// addVlan adds a vlan to a device
func (d *deviceInfo) addVlan(vlanID uint16) {
	// add entry if it does not exist
	if d.vlans[vlanID] == nil {
		debug("Adding new vlan to an entry")
		vlan := vnetInfo{}
		vlan.ID = uint32(vlanID)
		d.vlans[vlanID] = &vlan
	}
}
