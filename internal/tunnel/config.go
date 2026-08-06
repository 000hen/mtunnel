// Package tunnel orchestrates the host and client roles, wiring libp2p discovery
// (p2p), the per-network forwarders (tcp, udp), and the control channel (control)
// together.
package tunnel

import (
	"time"

	"mtunnel-libp2p/internal/p2p"
	"mtunnel-libp2p/internal/tier"

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

	// DefaultPunchAttempts is how many times a session punches before settling for the
	// libp2p relay.
	//
	// Two, not one, because ICE against a real NAT is probabilistic rather than
	// deterministic: a mapping the peer's probe arrived too early for on the first pass
	// is usually there on the second, and a first attempt that lost its STUN replies to
	// ordinary UDP loss has nothing wrong with it that trying again does not fix. The
	// cost of the extra attempt is bounded and only paid by sessions that were heading
	// for the relay anyway - which is a far worse outcome than a few seconds of startup.
	//
	// Not more than two, because past that the failures left are structural (symmetric
	// NAT on both sides, UDP blocked outright) and no number of attempts will fix them;
	// they need the relay, and making them wait longer to reach it helps nobody.
	//
	// Exported because it is the -punch-attempts flag's default, which the CLI needs to
	// state before it has an Options to ask.
	DefaultPunchAttempts uint8 = 2
)

// DefaultHandshakeTimeout bounds how long a tier above the floor has to prove
// itself before the cascade moves on. It is re-exported from internal/tier, where
// the rungs that spend it live, because it is also the -handshake-timeout flag's
// default and the CLI needs to state it before it has an Options to ask - and
// because a second constant with the same job is a second constant to forget.
const DefaultHandshakeTimeout = tier.DefaultHandshakeTimeout

// Options carries policies selected at the CLI boundary into orchestration.
type Options struct {
	P2P       p2p.Config
	Bandwidth *metrics.BandwidthCounter

	// STUNServers, PunchTimeout and PunchGatherTimeout configure the independent ICE
	// hole punch (internal/nat). They sit here rather than in P2P because the punch is
	// deliberately libp2p-free - libp2p only carries the credential exchange - and
	// p2p.Config is documented as libp2p's own settings.
	//
	// PunchTimeout bounds connectivity checks and PunchGatherTimeout bounds candidate
	// gathering; they are separate because the two phases fail on completely different
	// timescales. A nil STUNServers means nat.DefaultSTUNServers, a zero PunchTimeout
	// means nat.DefaultTimeout, and a zero PunchGatherTimeout means the smaller of
	// PunchTimeout and nat.DefaultGatherTimeout.
	STUNServers        []string
	PunchTimeout       time.Duration
	PunchGatherTimeout time.Duration

	// PunchAttempts is how many times this side will punch before taking the libp2p
	// floor. It is advertised in the Hello and the effective count is the smaller of the
	// two sides' - see negotiate.EffectivePunchAttempts - because the retry has to be a
	// joint decision, not a local one. Zero means DefaultPunchAttempts.
	PunchAttempts uint8

	// HandshakeTimeout bounds each tier's own handshake once the punch has produced
	// a substrate. Zero means DefaultHandshakeTimeout, resolved by tier.Params rather
	// than here, so every rung reads the budget from one place.
	HandshakeTimeout time.Duration
}
