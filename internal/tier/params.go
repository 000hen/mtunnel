package tier

import "time"

// DefaultHandshakeTimeout bounds how long a rung has to prove itself before the
// cascade moves on. WireGuard's Noise-IK is a 1-RTT exchange over an
// already-punched path, so a working tier lands in milliseconds; this is sized to
// cover one of wireguard-go's own 5s retransmits (RekeyTimeout) plus slack, so a
// single dropped initiation costs a retry rather than the tier.
const DefaultHandshakeTimeout = 6 * time.Second

// Params is what every tier in a Set shares: the budget a rung gets to come up in,
// and whether to emit diagnostic records.
//
// It is per-process rather than per-session, which is why it is held by the
// implementation and not passed in Session.
type Params struct {
	// HandshakeTimeout bounds one rung's handshake. Zero means
	// DefaultHandshakeTimeout.
	HandshakeTimeout time.Duration
	// Diagnostic enables the tier packages' own slog records.
	Diagnostic bool
}

// handshakeTimeout resolves the configured budget, so each tier reads one value
// rather than repeating the zero check.
func (p Params) handshakeTimeout() time.Duration {
	if p.HandshakeTimeout <= 0 {
		return DefaultHandshakeTimeout
	}
	return p.HandshakeTimeout
}
