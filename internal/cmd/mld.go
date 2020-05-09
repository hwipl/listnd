package cmd

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// mld packet constants
const mldv2IsEx = layers.MLDv2MulticastAddressRecordTypeModeIsExcluded
const mldv2ToEx = layers.MLDv2MulticastAddressRecordTypeChangeToExcludeMode
const mldv2IsIn = layers.MLDv2MulticastAddressRecordTypeModeIsIncluded
const mldv2ToIn = layers.MLDv2MulticastAddressRecordTypeChangeToIncludeMode

// parseMld parses mld packets
func parseMld(packet gopacket.Packet) {
	// MLDv1
	qlv1 := packet.Layer(layers.LayerTypeMLDv1MulticastListenerQuery)
	if qlv1 != nil {
		debug("MLDv1 Query Message")
		// queries are sent by routers, mark as router
		linkSrc, _ := getMacs(packet)
		netSrc, _ := getIps(packet)
		dev := devices.Get(linkSrc)
		dev.ips.Add(netSrc)
		dev.router.enable()
		dev.router.setTimestamp(packet.Metadata().Timestamp)
		return
	}

	dlv1 := packet.Layer(layers.LayerTypeMLDv1MulticastListenerDone)
	if dlv1 != nil {
		debug("MLDv1 Done Message")
		// parse and remove multicast address
		done, _ := dlv1.(*layers.MLDv1MulticastListenerDoneMessage)
		linkSrc, _ := getMacs(packet)
		netSrc, _ := getIps(packet)
		dev := devices.Get(linkSrc)
		dev.ips.Add(netSrc)
		dev.ips.Del(layers.NewIPEndpoint(done.MulticastAddress))
		return
	}

	rlv1 := packet.Layer(layers.LayerTypeMLDv1MulticastListenerReport)
	if rlv1 != nil {
		debug("MLDv1 Report Message")
		// parse and add multicast address
		report, _ := rlv1.(*layers.MLDv1MulticastListenerReportMessage)
		linkSrc, _ := getMacs(packet)
		netSrc, _ := getIps(packet)
		dev := devices.Get(linkSrc)
		dev.ips.Add(netSrc)
		dev.ips.Add(layers.NewIPEndpoint(report.MulticastAddress))
		return
	}

	// MLDv2
	qlv2 := packet.Layer(layers.LayerTypeMLDv2MulticastListenerQuery)
	if qlv2 != nil {
		debug("MLDv2 Query Message")
		// queries are sent by routers, mark as router
		linkSrc, _ := getMacs(packet)
		netSrc, _ := getIps(packet)
		dev := devices.Get(linkSrc)
		dev.ips.Add(netSrc)
		dev.router.enable()
		dev.router.setTimestamp(packet.Metadata().Timestamp)
		return
	}

	rlv2 := packet.Layer(layers.LayerTypeMLDv2MulticastListenerReport)
	if rlv2 != nil {
		debug("MLDv2 Report Message")
		report, _ := rlv2.(*layers.MLDv2MulticastListenerReportMessage)
		linkSrc, _ := getMacs(packet)
		netSrc, _ := getIps(packet)
		dev := devices.Get(linkSrc)
		dev.ips.Add(netSrc)

		// parse multicast addresses and add/remove them
		for _, v := range report.MulticastAddressRecords {
			switch v.RecordType {
			case mldv2IsEx, mldv2ToEx:
				// add IP
				dev.ips.Add(layers.NewIPEndpoint(
					v.MulticastAddress))
			case mldv2IsIn, mldv2ToIn:
				// remove IP
				dev.ips.Del(layers.NewIPEndpoint(
					v.MulticastAddress))
			}
		}
		return
	}
}
