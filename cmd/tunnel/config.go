package main

import (
	"fmt"
	"time"
)

const (
	protocolID                = "/mtunnel/1.0.0"
	networkStabilizationDelay = 20 * time.Second
	defaultLocalDialTimeout   = 10 * time.Second

	// streamOpenTimeout bounds how long the client waits when opening a tunnel
	// stream to the host (which may involve dialing/upgrading the connection).
	streamOpenTimeout = 30 * time.Second

	// DHT peer discovery retry settings. A host's address record may take a
	// while to propagate, so the client retries the lookup before giving up.
	dhtLookupTimeout     = 30 * time.Second
	dhtLookupRetryDelay  = 5 * time.Second
	dhtLookupMaxAttempts = 6
)

var supportedNetworks = map[string]struct{}{
	"tcp": {},
	"udp": {},
}

func validateNetworkType(network string) error {
	if _, ok := supportedNetworks[network]; ok {
		return nil
	}

	return fmt.Errorf("unsupported network type %q", network)
}
