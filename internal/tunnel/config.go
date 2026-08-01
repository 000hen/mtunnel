// Package tunnel orchestrates the host and client roles, wiring libp2p discovery
// (p2p), the per-network forwarders (tcp, udp), and the control channel (control)
// together.
package tunnel

import (
	"time"

	"mtunnel-libp2p/internal/p2p"

	"github.com/libp2p/go-libp2p/core/metrics"
)

const (
	// networkStabilizationDelay bounds how long the host waits for a dialable
	// (public or relay) address before announcing its token. It is an upper bound
	// rather than a fixed wait: the host proceeds as soon as such an address appears
	// (see p2p.WaitForNetworkReady).
	networkStabilizationDelay = 20 * time.Second

	// defaultLocalDialTimeout bounds how long the host waits when dialing its local
	// service for an inbound tunnel stream.
	defaultLocalDialTimeout = 10 * time.Second

	// negotiateTimeout bounds a single tier-negotiation phase. Opening the stream is
	// already bounded separately (p2p.streamOpenTimeout); this covers the exchange
	// that follows, which is one small round trip and needs nothing like this long.
	//
	// Without it the phase would inherit the run context, which is only cancelled at
	// shutdown: a peer that opens the stream and then stalls - a buggy peer, a relay
	// hiccup, or one deliberately withholding its reply - would block client startup
	// forever on one side and pin a handler goroutine for the process lifetime on the
	// other. The whole point of tier negotiation is that it can fail without taking
	// the session with it, and a hang is a worse failure than an error.
	negotiateTimeout = 10 * time.Second

	// punchExchangeTimeout bounds the PunchInfo swap, the negotiate stream's second
	// phase. It is more generous than negotiateTimeout because each side only sends
	// once its own ICE gathering has finished, so this covers the peer's gathering as
	// well as the round trip.
	punchExchangeTimeout = 20 * time.Second

	// DefaultHandshakeTimeout bounds how long the client waits for a tier above the
	// floor to prove itself before falling back. WireGuard's Noise-IK is a 1-RTT
	// exchange over an already-punched path, so a working tier lands in milliseconds;
	// this is sized to cover one of wireguard-go's own 5s retransmits (RekeyTimeout)
	// plus slack, so a single dropped initiation costs a retry rather than the tier.
	//
	// Exported because it is the -handshake-timeout flag's default, which the CLI
	// needs to state before it has an Options to ask.
	DefaultHandshakeTimeout = 6 * time.Second
)

// Options carries policies selected at the CLI boundary into orchestration.
type Options struct {
	P2P       p2p.Config
	Bandwidth *metrics.BandwidthCounter

	// STUNServers and PunchTimeout configure the independent ICE hole punch
	// (internal/nat). They sit here rather than in P2P because the punch is
	// deliberately libp2p-free - libp2p only carries the credential exchange - and
	// p2p.Config is documented as libp2p's own settings.
	//
	// A nil STUNServers means nat.DefaultSTUNServers; a zero PunchTimeout means
	// nat.DefaultTimeout.
	STUNServers  []string
	PunchTimeout time.Duration

	// HandshakeTimeout bounds each tier's own handshake once the punch has produced
	// a substrate. Zero means DefaultHandshakeTimeout.
	HandshakeTimeout time.Duration
}

// handshakeTimeout resolves the configured tier-handshake budget, so the ladder
// reads one value rather than repeating the zero check at every attempt.
func (o Options) handshakeTimeout() time.Duration {
	if o.HandshakeTimeout <= 0 {
		return DefaultHandshakeTimeout
	}
	return o.HandshakeTimeout
}
