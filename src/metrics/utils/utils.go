package utils

import (
	"strings"
	"time"
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
	} else if strings.Contains(userAgent, "prysm") {
		// Prysm UserAgent Example: "Prysm/v1.1.0/9b367b36fc12ecf565ad649209aa2b5bba8c7797"
		client = "Prysm"
		s := strings.Split(userAgent, "/")
		version = s[1]
	} else if strings.Contains(userAgent, "teku") {
		client = "Teku"
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

func GetTimeMiliseconds() int64 {
	return time.Now().UnixNano() / 1000000
}
