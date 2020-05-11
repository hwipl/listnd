package cmd

import (
	"fmt"
	"io"
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
		device.powerline.name = "Powerline"
		device.bridge.name = "Bridge"
		device.dhcp.name = "DHCP Server"
		device.router.name = "Router"
		device.ucasts.name = "Unicast Addresses"
		device.mcasts.name = "Multicast Addresses"
		device.macPeers.name = "MAC Peers"
		device.ipPeers.name = "IP Peers"
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

// Print prints all devices to w
func (d *deviceMap) Print(w io.Writer) {
	devicesFmt := "===================================" +
		"===================================\n" +
		"Devices: %-39d (pkts: %d)\n" +
		"===================================" +
		"===================================\n"
	fmt.Fprintf(w, devicesFmt, len(devices.m), devices.packets)
	for _, device := range devices.m {
		device.Print(w)
		fmt.Fprintln(w)
	}
}
