package tier

import (
	"context"
	"errors"
	"net"

	"mtunnel-libp2p/internal/negotiate"
	"mtunnel-libp2p/internal/quictun"
)

// quicTier is the second rung: a QUIC connection over the punched substrate,
// carrying either streams or DATAGRAM frames.
type quicTier struct {
	identity *quictun.Identity
	params   Params
}

// newQUIC returns the QUIC tier, holding this process's self-signed leaf for every
// session it will serve. Unexported for the same reason newWireGuard is: a tier is
// reached through a Set.
func newQUIC(identity QUICIdentity, params Params) Tier {
	return quicTier{identity: identity.Identity, params: params}
}

func (quicTier) ID() negotiate.Tier { return negotiate.TierQUIC }

func (quicTier) SubstrateAbandoned(err error) bool {
	return errors.Is(err, quictun.ErrSubstrateAbandoned)
}

// Dial completes a QUIC handshake on the shared substrate. Unlike WireGuard there
// is no separate readiness wait: the handshake either completes within its own
// budget or the tier has failed.
func (t quicTier) Dial(ctx context.Context, substrate net.Conn, s Session) (Rung, Outcome, error) {
	tun, err := quictun.Dial(ctx, substrate, t.config(s))
	if err != nil {
		// No failed() here: quictun.Dial unwinds its own partial construction and folds
		// an abandoned substrate into the error it returns, so there is nothing left to
		// release - only a phase to name.
		return Rung{}, phaseFor(t, OutcomeHandshakeFailed, err), err
	}
	return Rung{Opener: tun, Close: tun.Close}, OutcomeConnected, nil
}

// Serve accepts the client's QUIC handshake. It blocks until the client dials,
// which is why the host acknowledges the rung before calling it.
func (t quicTier) Serve(ctx context.Context, substrate net.Conn, s Session) (Rung, Outcome, error) {
	tun, err := quictun.Accept(ctx, substrate, t.config(s))
	if err != nil {
		// quictun.Accept unwinds itself, so as on the client there is only a phase to
		// name - and an abandoned substrate to name it instead.
		return Rung{}, phaseFor(t, OutcomeHandshakeFailed, err), err
	}
	return Rung{Acceptor: tun, Close: tun.Close}, OutcomeServing, nil
}

// config is shared by both roles so the two sides cannot drift apart on datagram
// support, which is negotiated inside the handshake and fails the tier if it does
// not match.
func (t quicTier) config(s Session) quictun.Config {
	return quictun.Config{
		Identity:        t.identity,
		PeerFingerprint: s.PeerQUICFingerprint,
		Datagrams:       s.Network.Datagram(),
		// One budget covers every tier's handshake, so the ladder's worst case stays
		// predictable. It must also stay comfortably under the negotiate phase timeout:
		// the host spends it inside quictun.Accept, unable to read the next Attempt, and
		// the client is waiting for the acknowledgement of exactly that message.
		HandshakeTimeout: t.params.handshakeTimeout(),
		Diagnostic:       t.params.Diagnostic,
	}
}
