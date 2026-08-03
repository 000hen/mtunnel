// Package negotiate defines the tunnel-tier handshake exchanged once per session
// between host and client. It selects which data-plane protocol carries forwarded
// traffic (WireGuard, QUIC, or the libp2p-stream floor).
//
// Like internal/transport it is a leaf package: it imports only the standard
// library and has no libp2p dependency, so the tier-selection logic stays
// unit-testable and network-agnostic. The wire format is gob, matching the
// connection token (internal/p2p/token.go) - both are exchanged between two
// instances of this exact binary, unlike the external JSON control channel.
package negotiate

import (
	"context"
	"encoding/gob"
	"fmt"
	"io"
)

// Tier names a tunnel data-plane protocol. The cascade priority is fixed:
// WireGuard is preferred over QUIC, which is preferred over the libp2p floor.
type Tier string

const (
	TierWireGuard Tier = "wireguard"
	TierQUIC      Tier = "quic"
	// TierLibp2p is the guaranteed floor: both sides always advertise it, so tier
	// selection never fails to resolve to something usable.
	TierLibp2p Tier = "libp2p"
)

// cascade lists tiers in descending priority. SelectTier walks it in order and
// returns the first tier both sides support.
var cascade = []Tier{TierWireGuard, TierQUIC, TierLibp2p}

// Hello is the first negotiate message, always exchanged. SupportedTiers lists the
// tiers this side can speak; WireGuardPubKey is this side's static X25519 public key
// (used only when the resolved tier is WireGuard).
type Hello struct {
	SupportedTiers  []Tier
	WireGuardPubKey [32]byte

	// PunchProbe asks for a measurement-only NAT punch after tier selection: both
	// sides exchange PunchInfo and attempt an ICE connection purely to record the
	// outcome, then discard it. It exists because the punch has to be proven against
	// real NATs before any tier depends on it.
	//
	// The probe runs only when both sides set this, which is what keeps the stream in
	// lockstep. That also makes it safe against a peer predating the field: gob
	// decodes the absent field as false, so the newer side skips the extra phase the
	// older side would never reach.
	PunchProbe bool

	// PunchAttempts is how many times this side is willing to punch before giving up
	// and taking the libp2p floor. ICE against a real NAT is probabilistic - a mapping
	// that was not there on the first pass is often there on the second - so a single
	// attempt discards recovery that costs nothing but a few seconds.
	//
	// The effective count is PunchAttempts(min) of the two sides, via EffectivePunchAttempts,
	// for the same reason PunchProbe is an AND: the two sides walk this loop in lockstep
	// and a side that gave up early would leave the other reading a message type its
	// peer will never send. Zero means one attempt, which is both the natural floor and
	// what a peer predating the field decodes to - pinning that pairing to today's
	// behaviour.
	PunchAttempts uint8
}

// PunchOutcome reports whether this side's punch attempt produced a usable substrate.
// It is exchanged only when both sides agreed on more than one attempt.
//
// It exists because "retry on failure" is not a local decision here. Each side runs its
// own ICE agent against its own NAT, and the two do not have to fail together: the
// client's Connect can succeed microseconds before the host's context expires. Without
// this swap the winner would carry on to send an Attempt while the loser looped back to
// gather again, and the two would be reading different message types off the same
// stream - a hang, not a fallback. Retrying only when both sides report OK keeps them on
// the same rung of the same ladder.
type PunchOutcome struct {
	OK bool
}

// EffectivePunchAttempts resolves how many punch attempts the two sides will make. It
// is the smaller of the two requests, with zero - the value gob produces for a peer that
// predates the field - meaning one.
//
// Both sides call it with the same pair of numbers and so reach the same answer without
// a further round trip, exactly as SharedCascade does for tiers.
func EffectivePunchAttempts(local, peer uint8) uint8 {
	if local == 0 {
		local = 1
	}
	if peer == 0 {
		peer = 1
	}
	return min(local, peer)
}

// PunchInfo is the second negotiate message, exchanged only when the selected tier
// needs an independent NAT punch (WireGuard or QUIC).
//
// QUICCertFingerprint is the SHA-256 of this side's self-signed leaf certificate. The
// QUIC tier pins the peer to exactly that certificate instead of validating a chain
// it has no CA for, and this stream is what makes that meaningful: it rides an
// authenticated Noise-encrypted libp2p stream, so the value arrives already trusted.
type PunchInfo struct {
	ICEUfrag, ICEPwd    string
	ICECandidates       []string
	QUICCertFingerprint []byte
}

// Attempt names the rung the client is about to try on the shared punched substrate.
//
// Unlike Hello and PunchInfo this message travels one way only, and that asymmetry is
// the point. The cascade is walked by the client - it is the side that dials, and the
// side that finds out a rung failed - while the host has to be told, because a QUIC
// listener and a WireGuard device are different things to stand up and it cannot
// guess which one is coming. Both sides compute the same SharedCascade, so this is not
// a decision being communicated so much as a position in an agreed sequence.
//
// TierLibp2p as the attempt means the client has given up on the punched substrate
// and fallen to the floor; the host tears the substrate down and does nothing further,
// its libp2p handler already being live.
type Attempt struct {
	Tier Tier
}

// SharedCascade returns every tier both sides support, in descending priority. It is
// the ladder the client walks: try the head, and on failure try the next.
//
// TierLibp2p is always the last element even if a side somehow omitted it, because
// the floor is not really a negotiated capability - it is what both processes are
// already running, and a cascade that could run out of rungs would turn an optional
// upgrade into a new way for a working tunnel to fail.
func SharedCascade(local, peer []Tier) []Tier {
	localSet := toSet(local)
	peerSet := toSet(peer)

	shared := make([]Tier, 0, len(cascade))
	for _, t := range cascade {
		if t == TierLibp2p {
			continue
		}
		if localSet[t] && peerSet[t] {
			shared = append(shared, t)
		}
	}
	return append(shared, TierLibp2p)
}

// SelectTier returns the highest-priority tier present in both local and peer,
// following the fixed cascade WireGuard > QUIC > libp2p. Because both sides always
// include TierLibp2p, it always resolves - when there is no shared non-libp2p tier
// it returns TierLibp2p.
//
// It is the head of SharedCascade, and exists separately because that is what the
// diagnostic record and the control channel report: the tier the session intends to
// use, decided before any of it is attempted.
func SelectTier(local, peer []Tier) Tier {
	return SharedCascade(local, peer)[0]
}

func toSet(tiers []Tier) map[Tier]bool {
	set := make(map[Tier]bool, len(tiers))
	for _, t := range tiers {
		set[t] = true
	}
	return set
}

// An Exchange carries every negotiate phase over one stream. Both phases must share
// a single encoder/decoder pair: gob.NewDecoder wraps a reader that is not an
// io.ByteReader (a libp2p stream is not) in a bufio.Reader, so a decoder built fresh
// per phase would discard bytes the previous decoder had already buffered - the
// second phase would then read garbage or hang. Holding the pair for the stream's
// lifetime avoids that entirely.
//
// Every phase is symmetric: both sides send before either receives, so the stream
// underneath must buffer a whole message without a concurrent read. Real streams do
// (a socket's send buffer, a libp2p stream's flow-control window), and every message
// here is far below those limits - keep it that way when adding phases. An unbuffered
// io.Pipe or net.Pipe deadlocks and is not a valid substrate.
//
// An Exchange is not safe for concurrent use, and must not be reused after a call
// returns a context error: the abandoned encode/decode may still be in flight.
type Exchange struct {
	enc *gob.Encoder
	dec *gob.Decoder
}

// NewExchange binds an Exchange to rw. The caller retains ownership of rw and is
// responsible for closing it, which is also what unblocks an in-flight phase when
// its context is cancelled.
func NewExchange(rw io.ReadWriter) *Exchange {
	return &Exchange{enc: gob.NewEncoder(rw), dec: gob.NewDecoder(rw)}
}

// Negotiate exchanges Hello messages and returns the resolved tier and the peer's
// Hello. Both sides call it identically - send, then receive - which is what lets
// both reach the same answer with no extra round trip.
func (x *Exchange) Negotiate(ctx context.Context, local Hello) (Tier, Hello, error) {
	peer, err := swap(ctx, x, local, "hello")
	if err != nil {
		return "", Hello{}, err
	}
	return SelectTier(local.SupportedTiers, peer.SupportedTiers), peer, nil
}

// ExchangePunchInfo swaps PunchInfo messages, mirroring Negotiate's symmetric
// write-then-read shape. It runs as a second phase on the same Exchange, and only
// when the resolved tier needs an independent NAT punch. No caller wires it up in
// this milestone; M2 is its first user.
func (x *Exchange) ExchangePunchInfo(ctx context.Context, local PunchInfo) (PunchInfo, error) {
	return swap(ctx, x, local, "punch info")
}

// ExchangePunchOutcome swaps PunchOutcome messages, in the same symmetric shape as
// every other phase, and reports whether *both* sides landed a substrate. Retrying is
// only safe when the answer is agreed - see PunchOutcome.
func (x *Exchange) ExchangePunchOutcome(ctx context.Context, ok bool) (bool, error) {
	peer, err := swap(ctx, x, PunchOutcome{OK: ok}, "punch outcome")
	if err != nil {
		return false, err
	}
	return ok && peer.OK, nil
}

// SendAttempt tells the peer which rung of the cascade is about to be tried on the
// shared punched substrate. Only the client sends it - see Attempt.
func (x *Exchange) SendAttempt(ctx context.Context, a Attempt) error {
	return send(ctx, x, a, "attempt")
}

// ReceiveAttempt waits for the peer's next Attempt. Only the host calls it.
func (x *Exchange) ReceiveAttempt(ctx context.Context) (Attempt, error) {
	return receive[Attempt](ctx, x, "attempt")
}

// send performs one asymmetric send over x, with the same cancellation shape as swap.
func send[T any](ctx context.Context, x *Exchange, local T, what string) error {
	done := make(chan error, 1)
	go func() {
		if err := x.enc.Encode(local); err != nil {
			done <- fmt.Errorf("send %s: %w", what, err)
			return
		}
		done <- nil
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

// receive performs one asymmetric receive over x.
func receive[T any](ctx context.Context, x *Exchange, what string) (T, error) {
	var zero T
	type result struct {
		msg T
		err error
	}
	done := make(chan result, 1)
	go func() {
		var msg T
		if err := x.dec.Decode(&msg); err != nil {
			done <- result{err: fmt.Errorf("receive %s: %w", what, err)}
			return
		}
		done <- result{msg: msg}
	}()

	select {
	case <-ctx.Done():
		return zero, ctx.Err()
	case res := <-done:
		if res.err != nil {
			return zero, res.err
		}
		return res.msg, nil
	}
}

// swap performs one symmetric send-then-receive round over x. ctx cancellation is
// honoured by returning early; the caller closes the stream, which unblocks the
// in-flight encode/decode. The result channel is buffered so that goroutine never
// leaks on the send.
func swap[T any](ctx context.Context, x *Exchange, local T, what string) (T, error) {
	var zero T
	type result struct {
		peer T
		err  error
	}
	done := make(chan result, 1)
	go func() {
		if err := x.enc.Encode(local); err != nil {
			done <- result{err: fmt.Errorf("send %s: %w", what, err)}
			return
		}
		var peer T
		if err := x.dec.Decode(&peer); err != nil {
			done <- result{err: fmt.Errorf("receive %s: %w", what, err)}
			return
		}
		done <- result{peer: peer}
	}()

	select {
	case <-ctx.Done():
		return zero, ctx.Err()
	case res := <-done:
		if res.err != nil {
			return zero, res.err
		}
		return res.peer, nil
	}
}
