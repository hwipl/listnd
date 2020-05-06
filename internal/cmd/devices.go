package cmd

import (
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// variable definitions
var (
	// network device map
	packets     int
	devicesLock = &sync.Mutex{}
	devices     = make(deviceMap)
)

// vlanInfo stores vlan information
type vlanInfo struct {
	timeInfo
	vlan    uint16
	packets int
}

// vxlanInfo stores vxlan information
type vxlanInfo struct {
	timeInfo
	vxlan   uint32
	packets int
}

// geneveInfo stores geneve information
// TODO: common vnetInfo for vlan, vxlan, geneve?
type geneveInfo struct {
	timeInfo
	geneve  uint32
	packets int
}

// ipInfo stores an ip address of a device on the network
type ipInfo struct {
	timeInfo
	ip      gopacket.Endpoint
	packets int
}

// prefixInfo stores a router's prefix information
type prefixInfo struct {
	timeInfo
	prefix layers.ICMPv6Option
}

// powerlineInfo stores powerline information
type powerlineInfo struct {
	propInfo
	timeInfo
}

// dhcpInfo stores dhcp information
type dhcpInfo struct {
	propInfo
	timeInfo
}

// bridgeInfo stores bridge information
type bridgeInfo struct {
	propInfo
	timeInfo
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
	ips       map[gopacket.Endpoint]*ipInfo
	macPeers  map[gopacket.Endpoint]*ipInfo
	ipPeers   map[gopacket.Endpoint]*ipInfo
}

// deviceMap is the device table definition
type deviceMap map[gopacket.Endpoint]*deviceInfo

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
		ip := ipInfo{}
		ip.ip = netAddr
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
			ip := ipInfo{}
			ip.ip = addr
			d.macPeers[addr] = &ip
		}
	case layers.EndpointIPv4, layers.EndpointIPv6:
		if d.ipPeers[addr] == nil {
			debug("Adding new ip peer to an entry")
			ip := ipInfo{}
			ip.ip = addr
			d.ipPeers[addr] = &ip
		}
	}
}

// add adds a device to the device table
func (d deviceMap) add(linkAddr gopacket.Endpoint) {
	// create table entries if necessary
	if d[linkAddr] == nil {
		debug("Adding new entry")
		device := deviceInfo{}
		device.mac = linkAddr
		device.vlans = make(map[uint16]*vlanInfo)
		device.vxlans = make(map[uint32]*vxlanInfo)
		device.geneves = make(map[uint32]*geneveInfo)
		device.ips = make(map[gopacket.Endpoint]*ipInfo)
		device.macPeers = make(map[gopacket.Endpoint]*ipInfo)
		device.ipPeers = make(map[gopacket.Endpoint]*ipInfo)
		d[linkAddr] = &device
	}
}

// addMacIP adds a device table entry with mac and ip address
func (d deviceMap) addMacIP(linkAddr, netAddr gopacket.Endpoint) {
	d.add(linkAddr)
	d[linkAddr].addIP(netAddr)
}

// helper variables for checking if IP address in endpoint is valid
var addrZero gopacket.Endpoint
var addrUnspecv4 = layers.NewIPEndpoint(net.ParseIP("0.0.0.0"))
var addrUnspecv6 = layers.NewIPEndpoint(net.ParseIP("::"))

// endpointIsValidIP checks if IP address in endpoint is valid
func endpointIsValidIP(e gopacket.Endpoint) bool {
	if e == addrZero || e == addrUnspecv4 || e == addrUnspecv6 {
		return false
	}

	return true
}
