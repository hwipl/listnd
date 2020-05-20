package cmd

import (
	"bytes"
	"io/ioutil"
	"log"
	"net"
	"os"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/hwipl/listnd/internal/pkt"
)

func TestGetFirstPcapInterface(t *testing.T) {
	pcapDevice = ""
	getFirstPcapInterface()
	if pcapDevice == "" {
		t.Errorf("pcapDevice = \"\", want != \"\"")
	}
}

func TestListenPcap(t *testing.T) {
	// prepare creation of packet
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// create ethernet header
	srcMAC, err := net.ParseMAC("00:00:5e:00:53:01")
	if err != nil {
		log.Fatal(err)
	}
	dstMAC := srcMAC
	eth := layers.Ethernet{
		SrcMAC: srcMAC,
		DstMAC: dstMAC,
	}

	// serialize packet to buffer
	pktBuf := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(pktBuf, opts, &eth)
	if err != nil {
		log.Fatal(err)
	}
	packet := pktBuf.Bytes()

	// create temporary pcap file
	tmpFile, err := ioutil.TempFile("", "listen.pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	// write packets of fake tcp connection to pcap file
	w := pcapgo.NewWriter(tmpFile)
	w.WriteFileHeader(65536, layers.LinkTypeEthernet)
	w.WritePacket(gopacket.CaptureInfo{
		CaptureLength: len(packet),
		Length:        len(packet),
	}, packet)
	tmpFile.Close()

	// handle packet
	pkt.SetDevices(&devices)
	pcapFile = tmpFile.Name()
	listen()

	// check results
	var buf bytes.Buffer
	devices.Print(&buf)
	want := "=================================================" +
		"=====================\n" +
		"Devices: 1                                       " +
		"(pkts: 1)\n" +
		"=================================================" +
		"=====================\n" +
		"MAC: 00:00:5e:00:53:01                           " +
		"(age: "
	got := buf.String()[:len(want)] // ignore age and pkt count
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}
}
