package main

import "time"

const (
	protocolID = "/mtunnel/1.0.0"

	// networkStabilizationDelay bounds how long the host waits for a dialable
	// (public or relay) address before announcing its token. It is an upper
	// bound rather than a fixed wait: the host proceeds as soon as such an
	// address appears (see waitForNetworkReady).
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

	// udpFlowIdleTimeout bounds how long a UDP flow (one client source address
	// and its dedicated tunnel stream) is kept alive without traffic. UDP has no
	// connection close, so idle flows are reaped to release their stream and
	// goroutines.
	udpFlowIdleTimeout = 60 * time.Second
)
