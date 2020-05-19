package cmd

import (
	"log"
	"net"
	"net/http"
)

var (
	httpListener net.Listener
)

// handleHTTP prints the device table to http clients
func handleHTTP(w http.ResponseWriter, r *http.Request) {
	flush := r.URL.Query().Get("flush")

	devices.Lock()
	devices.Print(w)
	if flush == "true" {
		devices.Reset()
	}
	devices.Unlock()
}

// startHTTP starts the http server
func startHTTP() {
	var err error

	// create listener
	httpListener, err = net.Listen("tcp", httpListen)
	if err != nil {
		log.Fatal(err)
	}

	// start listening
	http.HandleFunc("/", handleHTTP)
	go http.Serve(httpListener, nil)
}
