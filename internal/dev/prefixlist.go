package dev

import (
	"fmt"
	"io"

	"github.com/gopacket/gopacket/layers"
)

// PrefixList stores router prefixes
type PrefixList struct {
	Prefixes []*PrefixInfo
}

// Clear deletes all prefixes
func (p *PrefixList) Clear() {
	p.Prefixes = nil
}

// Add adds a prefix
func (p *PrefixList) Add(prefix layers.ICMPv6Option) *PrefixInfo {
	pf := PrefixInfo{}
	pf.Prefix = prefix
	p.Prefixes = append(p.Prefixes, &pf)
	return &pf
}

// Get returns all prefixes
func (p *PrefixList) Get() []*PrefixInfo {
	return p.Prefixes
}

// Print prints all prefixes
func (p *PrefixList) Print(w io.Writer) {
	for _, prefix := range p.Prefixes {
		fmt.Fprintf(w, "      %s\n", prefix)
	}
}
