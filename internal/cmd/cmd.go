package cmd

import (
	"flag"
	"fmt"

	"github.com/hwipl/listnd/internal/dev"
	"github.com/hwipl/listnd/internal/pkt"
)

var (
	// pcap settings
	pcapDevice  string
	pcapFile    string
	pcapPromisc bool = true
	pcapSnaplen int  = 1024
	pcapTimeout int  = 1

	// parsing/output settings
	interval  int  = 5
	debugMode bool = false
	withPeers bool = false

	// http
	httpListen string = ""

	// device table
	devices dev.DeviceMap
)

// parseCommandLine parses the command line arguments
func parseCommandLine() {
	// define command line arguments
	flag.StringVar(&pcapDevice, "i", pcapDevice,
		"set the interface to listen on")
	flag.StringVar(&pcapFile, "f", pcapFile,
		"set the pcap file to read packets from")
	flag.BoolVar(&pcapPromisc, "pcap-promisc", pcapPromisc,
		"set pcap promiscuous parameter")
	flag.IntVar(&pcapTimeout, "pcap-timeout", pcapTimeout,
		"set pcap timeout parameter in seconds")
	flag.IntVar(&pcapSnaplen, "pcap-snaplen", pcapSnaplen,
		"set pcap snapshot length parameter in bytes")
	flag.BoolVar(&debugMode, "debug", debugMode, "debugging mode")
	flag.BoolVar(&withPeers, "peers", withPeers, "show peers")
	flag.StringVar(&httpListen, "http", httpListen,
		"use http server and set the listen address (e.g.: :8000)")
	flag.IntVar(&interval, "interval", interval,
		"set output interval to `seconds`")

	// parse and overwrite default values of settings
	flag.Parse()

	// output settings
	debug(fmt.Sprintf("Pcap Listen Device: %s", pcapDevice))
	debug(fmt.Sprintf("Pcap Promiscuous: %t", pcapPromisc))
	debug(fmt.Sprintf("Pcap Timeout: %d", pcapTimeout))
	debug(fmt.Sprintf("Pcap Snaplen: %d", pcapSnaplen))
	debug(fmt.Sprintf("Debugging Output: %t", debugMode))
	debug(fmt.Sprintf("Peers Output: %t", withPeers))
}

// Run is the main entry point of listnd
func Run() {
	parseCommandLine()
	dev.SetDebug(debugMode)
	pkt.SetDebug(debugMode)
	pkt.SetDevices(&devices)
	pkt.SetPeers(withPeers)
	if httpListen != "" {
		// start http server and print device table to clients
		startHTTP()
	} else {
		// print device table periodically to console
		printConsole()
	}
	listen()
	printTable()
}
