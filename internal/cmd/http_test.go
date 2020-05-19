package cmd

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"testing"

	"github.com/google/gopacket/layers"
)

func getHTTPBody(url string) string {
	resp, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	return fmt.Sprintf("%s", body)
}

func TestHTTP(t *testing.T) {
	var want, got, url string

	// start server on random port
	httpListen = ":0"
	startHTTP()
	port := httpListener.Addr().(*net.TCPAddr).Port

	// get url with empty device table
	url = fmt.Sprintf("http://localhost:%d/", port)
	want = "=================================================" +
		"=====================\n" +
		"Devices: 0                                       " +
		"(pkts: 0)\n" +
		"=================================================" +
		"=====================\n"
	got = getHTTPBody(url)
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}

	// get url with filled device table
	mac, err := net.ParseMAC("00:00:5e:00:53:01")
	if err != nil {
		log.Fatal(err)
	}
	devices.Add(layers.NewMACEndpoint(mac))

	url = fmt.Sprintf("http://localhost:%d/", port)
	want = "=================================================" +
		"=====================\n" +
		"Devices: 1                                       " +
		"(pkts: 0)\n" +
		"=================================================" +
		"=====================\n" +
		"MAC: 00:00:5e:00:53:01                           " +
		"(age: -1, pkts: 0)\n\n"
	got = getHTTPBody(url)
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}

	// get url (two times) with wrong flush, should not change reply
	url = fmt.Sprintf("http://localhost:%d/?flush=wrong", port)
	want = "=================================================" +
		"=====================\n" +
		"Devices: 1                                       " +
		"(pkts: 0)\n" +
		"=================================================" +
		"=====================\n" +
		"MAC: 00:00:5e:00:53:01                           " +
		"(age: -1, pkts: 0)\n\n"
	got = getHTTPBody(url)
	got = getHTTPBody(url)
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}

	// get url with flush
	url = fmt.Sprintf("http://localhost:%d/?flush=true", port)
	want = "=================================================" +
		"=====================\n" +
		"Devices: 1                                       " +
		"(pkts: 0)\n" +
		"=================================================" +
		"=====================\n" +
		"MAC: 00:00:5e:00:53:01                           " +
		"(age: -1, pkts: 0)\n\n"
	got = getHTTPBody(url)
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}

	// get url again after flush, should return empty table
	url = fmt.Sprintf("http://localhost:%d/", port)
	want = "=================================================" +
		"=====================\n" +
		"Devices: 0                                       " +
		"(pkts: 0)\n" +
		"=================================================" +
		"=====================\n"
	got = getHTTPBody(url)
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}
}
