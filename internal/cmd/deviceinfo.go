package cmd

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	// helper variables for checking if IP address in endpoint is valid
	addrZero     gopacket.Endpoint
	addrUnspecv4 = layers.NewIPEndpoint(net.ParseIP("0.0.0.0"))
	addrUnspecv6 = layers.NewIPEndpoint(net.ParseIP("::"))
)

// endpointIsValidIP checks if IP address in endpoint is valid
func endpointIsValidIP(e gopacket.Endpoint) bool {
	if e == addrZero || e == addrUnspecv4 || e == addrUnspecv6 {
		return false
	}

	return true
}

// deviceInfo is a device found on the network
type deviceInfo struct {
	timeInfo
	mac       gopacket.Endpoint
	vlans     map[uint16]*vlanInfo
	vxlans    map[uint32]*vxlanInfo
	geneves   map[uint32]*geneveInfo
	powerline powerlineInfo
	bridge    bridgeInfo
	dhcp      dhcpInfo
	router    routerInfo
	packets   int
	ips       map[gopacket.Endpoint]*AddrInfo
	macPeers  map[gopacket.Endpoint]*AddrInfo
	ipPeers   map[gopacket.Endpoint]*AddrInfo
}

// addVlan adds a vlan to a device
func (d *deviceInfo) addVlan(vlanID uint16) {
	// add entry if it does not exist
	if d.vlans[vlanID] == nil {
		debug("Adding new vlan to an entry")
		vlan := vlanInfo{}
		vlan.vlan = vlanID
		d.vlans[vlanID] = &vlan
	}
}

// addVxlan adds a vxlan to a device
func (d *deviceInfo) addVxlan(vni uint32) {
	// add entry if it does not et
	if d.vxlans[vni] == nil {
		debug("Adding new vxlan to an entry")
		vxlan := vxlanInfo{}
		vxlan.vxlan = vni
		d.vxlans[vni] = &vxlan
	}
}

// addGeneve adds a geneve to a device
func (d *deviceInfo) addGeneve(vni uint32) {
	// add entry if it does not exist
	if d.geneves[vni] == nil {
		debug("Adding new geneve to an entry")
		geneve := geneveInfo{}
		geneve.geneve = vni
		d.geneves[vni] = &geneve
	}
}

// addIP adds an ip address to a device
func (d *deviceInfo) addIP(netAddr gopacket.Endpoint) {
	// make sure address is valid
	if !endpointIsValidIP(netAddr) {
		return
	}

	// add entry if it does not exist
	if d.ips[netAddr] == nil {
		debug("Adding new ip to an entry")
		ip := AddrInfo{}
		ip.Addr = netAddr
		d.ips[netAddr] = &ip
	}
}

// delIP removes an ip address from a device
func (d *deviceInfo) delIP(netAddr gopacket.Endpoint) {
	// make sure address is valid
	if !endpointIsValidIP(netAddr) {
		return
	}

	// remove entry if it exists
	if d.ips[netAddr] != nil {
		debug("Deleting ip from an entry")
		delete(d.ips, netAddr)
	}
}

// addPeer adds a peer address to a device
func (d *deviceInfo) addPeer(addr gopacket.Endpoint) {
	switch addr.EndpointType() {
	case layers.EndpointMAC:
		if d.macPeers[addr] == nil {
			debug("Adding new mac peer to an entry")
			// TODO: rename to addrInfo? add macInfo?
			ip := AddrInfo{}
			ip.Addr = addr
			d.macPeers[addr] = &ip
		}
	case layers.EndpointIPv4, layers.EndpointIPv6:
		if d.ipPeers[addr] == nil {
			debug("Adding new ip peer to an entry")
			ip := AddrInfo{}
			ip.Addr = addr
			d.ipPeers[addr] = &ip
		}
	}
}
