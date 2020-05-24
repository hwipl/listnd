# listnd

listnd is a command line tool for discovery of devices on a network and listing
them. The discovery process is passive in the sense that listnd does not send
any packets to discover devices on the network. Instead, it only captures
packets on a network interface and analyses them.

## Installation

You can download and install listnd with its dependencies to your GOPATH or
GOBIN with the go tool:

```console
$ go get github.com/hwipl/listnd/cmd/listnd
```

## Usage

You can run listnd with

```console
$ listnd
```

Make sure your user has the permission to capture traffic on the network
interface.

You can specify the network interface with the option `-i`. For example, you
can specify the interface `eth3` with:

```console
$ listnd -i eth3
```

Command line options of the `listnd` command:

```
  -debug
        set debugging mode
  -f file
        set the pcap file to read packets from
  -http address
        use http server and set the listen address (e.g.: :8000)
  -i interface
        set the interface to listen on
  -interval seconds
        set output interval to seconds (default 5)
  -pcap-filter filter
        set pcap packet filtering to filter
  -pcap-promisc
        set pcap promiscuous parameter (default true)
  -pcap-snaplen bytes
        set pcap snapshot length parameter to bytes (default 1024)
  -pcap-timeout seconds
        set pcap timeout parameter to seconds (default 1)
  -peers
        show peers
```

When listnd is running, it periodically prints the discovered devices and
information it was able to gather about them to the console.

## Examples

Running listnd on a small home network for a short period:

```console
$ sudo ./listnd -i eth3
[...]
======================================================================
Devices: 2                                       (pkts: 5246)
======================================================================
MAC: 5c:49:79:fe:dc:ba                           (age: 1, pkts: 3317)
  Properties:
    Router: true                                 (age: 122)
    Powerline: true                              (age: 2)
  Unicast Addresses:
    IP: 2001:c0ff:eec0:ffee:5e49:79ff:fefe:dcba  (age: 93, pkts: 1)
    IP: fe80::5e49:79ff:fefe:dcba                (age: 52, pkts: 1)
    IP: 192.168.1.1                              (age: 87, pkts: 12)
  Multicast Addresses:
    IP: 224.0.0.251                              (age: -1, pkts: 0)
    IP: 224.0.0.22                               (age: -1, pkts: 0)
    IP: 224.0.0.2                                (age: -1, pkts: 0)
    IP: 239.255.255.250                          (age: -1, pkts: 0)
    IP: 224.0.0.252                              (age: -1, pkts: 0)

MAC: 70:85:c2:ab:cd:ef                           (age: 1, pkts: 1929)
  Unicast Addresses:
    IP: 192.168.1.23                             (age: 1, pkts: 1842)
    IP: fe80::7285:c2ff:feab:cdef                (age: 52, pkts: 5)
```
