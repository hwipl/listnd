package cmd

import (
	"sync"

	"github.com/google/gopacket"
)

// variable definitions
var (
	// network device map
	devices deviceMap
)

// deviceMap is the device table definition
type deviceMap struct {
	sync.Mutex
	packets int
	m       map[gopacket.Endpoint]*deviceInfo
}

// add adds a device to the device table and returns the new device info entry
func (d *deviceMap) add(linkAddr gopacket.Endpoint) *deviceInfo {
	// create map if necessary
	if d.m == nil {
		d.m = make(map[gopacket.Endpoint]*deviceInfo)
	}
	// create table entries if necessary
	if d.m[linkAddr] == nil {
		debug("Adding new entry")
		device := deviceInfo{}
		device.mac = linkAddr
		device.vlans = make(map[uint16]*vnetInfo)
		d.m[linkAddr] = &device
	}
	return d.m[linkAddr]
}

// Get returns device information for device with linkAddr
func (d *deviceMap) Get(linkAddr gopacket.Endpoint) *deviceInfo {
	if d == nil {
		return nil
	}
	if d.m[linkAddr] == nil {
		return nil
	}
	return d.m[linkAddr]
}
