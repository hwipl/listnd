package dev

import (
	"fmt"
	"io"
)

// VNetMap stores mappings from vnet IDs to vnet information
type VNetMap struct {
	m map[uint32]*VNetInfo
}

// Add adds a vnet with id to the mapping and returns the vnet info
func (v *VNetMap) Add(id uint32) *VNetInfo {
	if v.m == nil {
		v.m = make(map[uint32]*VNetInfo)
	}
	if v.m[id] == nil {
		debug("Adding new vnet entry")
		vnet := VNetInfo{
			ID: id,
		}
		v.m[id] = &vnet
	}
	return v.m[id]
}

// Get returns the vnet info with id
func (v *VNetMap) Get(id uint32) *VNetInfo {
	if v.m == nil {
		return nil
	}
	return v.m[id]
}

// Len returns the number of vnets in the vnet map
func (v *VNetMap) Len() int {
	return len(v.m)
}

// Print prints the vnet map to w
func (v *VNetMap) Print(w io.Writer) {
	for _, vnet := range v.m {
		fmt.Fprintf(w, "    %s\n", vnet)
	}
}
