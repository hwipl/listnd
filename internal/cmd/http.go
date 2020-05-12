package cmd

import "net/http"

// handleHTTP prints the device table to http clients
func handleHTTP(w http.ResponseWriter, r *http.Request) {
	devices.Lock()
	devices.Print(w)
	devices.Unlock()
}

// startHTTP starts the http server
func startHTTP() {
	http.HandleFunc("/", handleHTTP)
	http.ListenAndServe(httpListen, nil)
}
