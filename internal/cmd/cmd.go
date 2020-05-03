package cmd

import (
	"flag"
	"fmt"

	"github.com/google/gopacket/pcap"
)

var (
	// pcap settings
	pcapPromisc bool   = true
	pcapDevice  string = "eth0"
	pcapSnaplen int    = 1024
	pcapTimeout int    = 1
	pcapHandle  *pcap.Handle
	pcapErr     error

	// parsing/output settings
	debugMode bool = false
	withPeers bool = false

	// http
	httpListen string = ""
)

// parseCommandLine parses the command line arguments
func parseCommandLine() {
	/* define command line arguments */
	flag.StringVar(&pcapDevice, "i", pcapDevice,
		"the interface to listen on")
	flag.BoolVar(&pcapPromisc, "pcap-promisc", pcapPromisc,
		"Set pcap promiscuous parameter")
	flag.IntVar(&pcapTimeout, "pcap-timeout", pcapTimeout,
		"Set pcap timeout parameter in seconds")
	flag.IntVar(&pcapSnaplen, "pcap-snaplen", pcapSnaplen,
		"Set pcap snapshot length parameter in bytes")
	flag.BoolVar(&debugMode, "debug", debugMode, "debugging mode")
	flag.BoolVar(&withPeers, "peers", withPeers, "show peers")
	flag.StringVar(&httpListen, "http", httpListen,
		"use http server and set the listen address (e.g.: :8000)")

	/* parse and overwrite default values of settings */
	flag.Parse()

	/* output settings */
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
	listen()
}
