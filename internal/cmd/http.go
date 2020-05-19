package cmd

import "net/http"

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
	http.HandleFunc("/", handleHTTP)
	go http.ListenAndServe(httpListen, nil)
}
