package cmd

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// AddrMap stores mappings of ip/mac addresses to address info
type AddrMap struct {
	m map[gopacket.Endpoint]*AddrInfo
}

// Add adds address to the AddrMap and returns the address info
func (a *AddrMap) Add(address gopacket.Endpoint) *AddrInfo {
	// check if address is valid
	switch address.EndpointType() {
	case layers.EndpointIPv4, layers.EndpointIPv6:
		if !endpointIsValidIP(address) {
			return nil
		}
	case layers.EndpointMAC:
		break
	default:
		// non IP/MAC addresses are not expected
		return nil
	}

	// create map if necessary
	if a.m == nil {
		a.m = make(map[gopacket.Endpoint]*AddrInfo)
	}
	// create table entry if necessary
	if a.m[address] == nil {
		debug("Adding new address entry")
		addr := AddrInfo{
			Addr: address,
		}
		a.m[address] = &addr
	}
	return a.m[address]
}

// Get returns address info with address
func (a *AddrMap) Get(address gopacket.Endpoint) *AddrInfo {
	if a.m == nil {
		return nil
	}
	return a.m[address]
}
