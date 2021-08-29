package utils

import (
	"strings"
	"time"
	"fmt"
	"errors"
	"net"
)

// Client utils
// Main function that will analyze the client type and verion out of the Peer UserAgent
// return the Client Type and it's verison (if determined)
func FilterClientType(userAgent string) (string, string) {
	var client string
	var version string
	// get the UserAgent in lowercases
	userAgent = strings.ToLower(userAgent)
	// check the client type
	if strings.Contains(userAgent, "lighthouse") { // the client is from Lighthouse
		// Lighthouse UserAgent Example: "Lighthouse/v1.0.3-65dcdc3/x86_64-linux"
		client = "Lighthouse"
		// Extract version
		s := strings.Split(userAgent, "/")
		aux := strings.Split(s[1], "-")
		version = aux[0]
	} else if strings.Contains(userAgent, "prysm") { // the client is from Prysm
		// Prysm UserAgent Example: "Prysm/v1.1.0/9b367b36fc12ecf565ad649209aa2b5bba8c7797"
		client = "Prysm"
		// Extract version
		s := strings.Split(userAgent, "/")
		version = s[1]
	} else if strings.Contains(userAgent, "teku") { // the client is from Prysm
		// Prysm UserAgent Example: "Prysm/v1.1.0/9b367b36fc12ecf565ad649209aa2b5bba8c7797"
		client = "Teku"
		// Extract version
		s := strings.Split(userAgent, "/")
		aux := strings.Split(s[2], "+")
		version = aux[0]
	} else if strings.Contains(userAgent, "nimbus") {
		client = "Nimbus"
		version = "Unknown"
	} else if strings.Contains(userAgent, "js-libp2p") {
		client = "Lodestar"
		s := strings.Split(userAgent, "/")
		version = s[1]
	} else if strings.Contains(userAgent, "unknown") {
		client = "Unknown"
		version = "Unknown"
	} else {
		client = "Unknown"
		version = "Unknown"
	}
	return client, version
}

// Get the Real Ip Address from the multi Address list
// TODO: Implement the Private IP filter in a better way
func GetFullAddress(multiAddrs []string) string {
	var address string
	if len(multiAddrs) > 0 {
		for _, element := range multiAddrs {
			if strings.Contains(element, "/ip4/192.168.") || strings.Contains(element, "/ip4/127.0.") || strings.Contains(element, "/ip6/") || strings.Contains(element, "/ip4/172.") || strings.Contains(element, "0.0.0.0") {
				continue
			} else {
				address = element
				break
			}
		}
	} else {
		address = "/ip4/127.0.0.1/tcp/9000"
	}
	return address
}

func GetTimeMiliseconds() int64 {
	now := time.Now()
	//secs := now.Unix()
	nanos := now.UnixNano()
	millis := nanos / 1000000

	return millis
}


func GetIPfromMultiaddress(multiaddr string) (ip string, err error) {
	s := strings.Split(multiaddr, "/")
	if len(s) < 3 {
		return ip, errors.New(fmt.Sprintf("Multiaddress doesn't include an IP: %s", multiaddr))
	}
	return s[2], nil
}


// IP public filtering 
var PrivateIPNetworks = []net.IPNet{
	net.IPNet{
		IP:   net.ParseIP("10.0.0.0"),
		Mask: net.CIDRMask(8, 32),
	},
	net.IPNet{
		IP:   net.ParseIP("172.16.0.0"),
		Mask: net.CIDRMask(12, 32),
	},
	net.IPNet{
		IP:   net.ParseIP("192.168.0.0"),
		Mask: net.CIDRMask(16, 32),
	},
}

func IsPublic(ip net.IP) bool {
	for _, ipNet := range PrivateIPNetworks {
		if ipNet.Contains(ip) || ip.IsLoopback() || ip.IsUnspecified() {
			return false
		}
	}
	return true
}