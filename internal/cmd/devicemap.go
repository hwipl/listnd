package cmd

import (
	"sync"

	"github.com/google/gopacket"
)

// variable definitions
var (
	// network device map
	packets     int
	devicesLock = &sync.Mutex{}
	devices     = make(deviceMap)
)

// deviceMap is the device table definition
type deviceMap map[gopacket.Endpoint]*deviceInfo

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

// Get returns device information for device with linkAddr
func (d deviceMap) Get(linkAddr gopacket.Endpoint) *deviceInfo {
	if d == nil {
		return nil
	}
	return d[linkAddr]
}

// addMacIP adds a device table entry with mac and ip address
func (d deviceMap) addMacIP(linkAddr, netAddr gopacket.Endpoint) {
	d.add(linkAddr)
	d[linkAddr].addIP(netAddr)
}
