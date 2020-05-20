package cmd

import (
	"os"
	"testing"

	"github.com/hwipl/listnd/internal/dev"
)

func TestRun(t *testing.T) {
	// create temporary pcap file
	pcapFile = testListenPcapCreateDumpFile()
	defer os.Remove(pcapFile)

	// make sure nothing panics
	devices = dev.DeviceMap{}
	Run()
}
