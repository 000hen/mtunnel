// Package tier holds the tunnel's data-plane implementations and the contract
// they share. A tier is one rung of the cascade: a protocol that carries
// forwarded connections over an already-punched net.Conn substrate.
//
// It is to the data plane what internal/transport is to the forwarded network -
// one interface, one implementation per kind, one registry (Set) that is the
// single source of truth for which kinds exist. Before it, every tier was spelled
// out in internal/tunnel as a pair of bespoke build functions, a switch arm in
// each of dialRung/standUpRung/supportedTiers, and a sentinel error the cascade
// had to know by name; adding one meant editing five places and remembering the
// fifth.
//
// Like every package below internal/tunnel it does not import libp2p: a tier runs
// on a plain net.Conn, and which library punched that conn is none of its
// business.
package tier

import (
	"context"
	"errors"
	"net"

	"mtunnel-libp2p/internal/negotiate"
	"mtunnel-libp2p/internal/transport"
)

// Tier is one rung of the data-plane cascade.
//
// The two build methods are separate rather than one call with a role flag
// because the roles are genuinely different constructions, not two settings of
// one: the client initiates a handshake and opens connections, the host listens
// and accepts them. Both take the *same* substrate - the cascade punches once and
// runs every rung on that one conn - so an implementation must never close it.
// Releasing it is the caller's job, after the last rung is done with it.
type Tier interface {
	// ID is the tier's name on the negotiate wire, and the value Set keys it by.
	ID() negotiate.Tier

	// Dial builds the client half on substrate and returns once the tier has
	// proven itself, so a rung that reports success is one that works.
	Dial(ctx context.Context, substrate net.Conn, s Session) (Rung, Outcome, error)

	// Serve builds the host half on substrate. It returns as soon as the tier is
	// listening, without waiting for the client: the host acknowledges a rung
	// before standing it up, and a rung that waited for its peer here would
	// deadlock against a client still waiting for that acknowledgement.
	Serve(ctx context.Context, substrate net.Conn, s Session) (Rung, Outcome, error)

	// SubstrateAbandoned reports whether err means this tier's teardown gave up on
	// releasing the shared substrate and closed it.
	//
	// It is a method rather than a package-level check against a shared sentinel
	// because no tier owns the substrate and no tier depends on another: each names
	// the condition with its own error, and this is where those separate answers are
	// made to mean the same thing. A caller that sees it true must stop climbing -
	// there is nothing left for the next rung to run on.
	SubstrateAbandoned(err error) bool
}

// Rung is one live tier: how forwarded connections travel over it, and what
// releases it.
//
// Dial fills Opener and Serve fills Acceptor - never both, because a rung serves
// one role. Close is always set, and never touches the shared substrate.
type Rung struct {
	// Opener opens one forwarded connection over the tier. Set by Dial.
	Opener transport.Opener
	// Acceptor yields the forwarded connections the peer started. Set by Serve.
	Acceptor Acceptor
	// Close releases everything the rung built, leaving the substrate usable by
	// the next rung. Never nil on a successful build.
	Close func() error
}

// Acceptor is the one thing a host-side tier has to offer: the next forwarded
// connection the peer started. It is the mirror of transport.Opener.
type Acceptor interface {
	AcceptStream(ctx context.Context) (transport.Stream, error)
}

// Session is what one negotiated session contributes to a tier: the peer material
// learned over the negotiate stream, plus the network being forwarded.
//
// It is per-session and per-peer. Everything a tier knows for its whole process
// lifetime - this side's keys, the handshake budget, the diagnostic flag - is
// held by the implementation instead, so a tier is constructed once and reused
// for every peer.
type Session struct {
	// Network is the forwarded network, which selects each tier's sub-mode: a
	// datagram network takes QUIC's DATAGRAM extension and WireGuard's virtual UDP
	// conn, a stream network takes QUIC streams and WireGuard's virtual TCP
	// listener. Both sides derive it from the token, so they cannot disagree.
	Network transport.Network

	// PeerWireGuardKey is the peer's static X25519 public key, from its Hello.
	PeerWireGuardKey [32]byte

	// PeerQUICFingerprint is the SHA-256 of the peer's self-signed QUIC leaf, from
	// its PunchInfo. Nothing is persisted between runs, so there is no CA to
	// validate against and this pin is what makes the QUIC tier authenticated; it
	// is trustworthy because the negotiate stream that carried it is itself
	// Noise-encrypted and peer-authenticated.
	PeerQUICFingerprint [32]byte
}

// Outcome names the phase a rung reached. It is the vocabulary of the
// tunnel_tier_attempt and tunnel_tier_fallback diagnostic records, and exists as
// a type because "wireguard failed" and "the punch never landed" call for
// completely different investigations - so the phase has to survive as a value,
// not as prose in a log line.
//
// Only OutcomeConnected and OutcomeServing mean success; every other value is
// meaningful alongside a non-nil error and names what stopped the attempt.
type Outcome string

const (
	// OutcomeConnected is a client-side rung that came up and proved itself.
	OutcomeConnected Outcome = "connected"
	// OutcomeServing is a host-side rung that is listening.
	OutcomeServing Outcome = "serving"

	// OutcomeSubstrateAbandoned means the rung's teardown closed the punched conn
	// every rung shares. It outranks whatever phase failed first, because it is the
	// only outcome the cascade acts on rather than merely records.
	OutcomeSubstrateAbandoned Outcome = "substrate-abandoned"

	// OutcomeDeviceFailed is a tier that could not be constructed at all.
	OutcomeDeviceFailed Outcome = "device-failed"
	// OutcomeMuxFailed is a datagram sub-mode whose virtual conn would not open.
	OutcomeMuxFailed Outcome = "mux-failed"
	// OutcomeListenFailed is a stream sub-mode whose virtual listener would not open.
	OutcomeListenFailed Outcome = "listen-failed"
	// OutcomeUpFailed is a tier that would not start passing packets.
	OutcomeUpFailed Outcome = "up-failed"
	// OutcomeHandshakeFailed is a tier that came up but never reached the peer.
	OutcomeHandshakeFailed Outcome = "handshake-failed"

	// OutcomePunchFailed is the shared NAT punch below every rung failing, which
	// ends the cascade before any tier is tried.
	OutcomePunchFailed Outcome = "punch-failed"
	// OutcomeRequestFailed is the negotiate stream breaking while agreeing which
	// rung is next - not a failure of the rung, but of the ability to pick another.
	OutcomeRequestFailed Outcome = "request-failed"
	// OutcomeUnsupported is a tier named on the wire that this side has no
	// implementation for.
	OutcomeUnsupported Outcome = "unsupported"
)

// Succeeded reports whether o names a rung that came up, for either role.
func (o Outcome) Succeeded() bool { return o == OutcomeConnected || o == OutcomeServing }

// failed releases a rung that did not come up and reports why, folding an
// abandoned substrate into both the outcome and the error.
//
// The rung has failed either way; what its teardown still decides is whether
// there is anything left for the next rung to run on.
func failed(t Tier, release func() error, phase Outcome, cause error) (Rung, Outcome, error) {
	if release == nil {
		return Rung{}, phase, cause
	}
	err := release()
	if !t.SubstrateAbandoned(err) {
		return Rung{}, phase, cause
	}
	return Rung{}, OutcomeSubstrateAbandoned, errors.Join(cause, err)
}

// phaseFor names the phase that ended an attempt, unless the failure took the
// substrate with it - in which case that is the more consequential fact and the
// one the caller has to act on.
func phaseFor(t Tier, phase Outcome, err error) Outcome {
	if t.SubstrateAbandoned(err) {
		return OutcomeSubstrateAbandoned
	}
	return phase
}
