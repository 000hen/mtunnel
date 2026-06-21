// Package tunnel orchestrates the host and client roles, wiring libp2p discovery
// (p2p), the per-network forwarders (tcp, udp), and the control channel (control)
// together.
package tunnel

import "time"

const (
	// networkStabilizationDelay bounds how long the host waits for a dialable
	// (public or relay) address before announcing its token. It is an upper bound
	// rather than a fixed wait: the host proceeds as soon as such an address appears
	// (see p2p.WaitForNetworkReady).
	networkStabilizationDelay = 20 * time.Second

	// defaultLocalDialTimeout bounds how long the host waits when dialing its local
	// service for an inbound tunnel stream.
	defaultLocalDialTimeout = 10 * time.Second
)
