package p2p

import (
	"fmt"

	"github.com/libp2p/go-libp2p/core/protocol"
)

// ProtocolGeneration is the wire generation of the tunnel's libp2p streams.
//
// Generation 1 is the original binary. This build is generation 2 and shares no
// protocol ID with it: the negotiate exchange, the tier cascade, and the token
// have all moved on, and two generations meeting on one protocol ID would
// half-negotiate before failing somewhere unhelpful. Separate IDs make the
// mismatch immediate - an original peer finds nothing registered and gives up at
// once, which is the failure that is actually diagnosable.
//
// It is deliberately not the same number as TokenVersion. The two version
// different things and are free to move independently; ProtocolsFor is the single
// place they meet.
const ProtocolGeneration = 2

// Protocols is the pair of libp2p protocol IDs one tunnel generation speaks.
//
// They travel together because they are two halves of one conversation: a peer
// that can negotiate a tier has to be the peer that then serves the data streams,
// and resolving them separately would let a version mismatch pass the first check
// and fail the second.
type Protocols struct {
	// Data carries forwarded connections on the libp2p floor - one stream per
	// forwarded connection.
	Data protocol.ID
	// Negotiate carries the tier handshake, opened once per session before any
	// data stream (see internal/negotiate).
	Negotiate protocol.ID
}

// ProtocolID identifies the tunnel stream protocol spoken between host and client
// by this build. It is the Data half of CurrentProtocols, named separately
// because the host registers and removes it by name.
const ProtocolID protocol.ID = "/mtunnel/2.0.0"

// NegotiateProtocolID identifies the tier-negotiation stream opened once per
// session, before any tunnel stream, to agree which data-plane tier carries
// forwarded traffic (see internal/negotiate).
const NegotiateProtocolID protocol.ID = "/mtunnel/negotiate/2.0.0"

// CurrentProtocols returns the protocol pair this build speaks and announces.
func CurrentProtocols() Protocols {
	return Protocols{Data: ProtocolID, Negotiate: NegotiateProtocolID}
}

// ProtocolsFor resolves the protocols a host advertising token version v speaks.
// It is the only place the token's version axis and the protocol's generation
// axis meet.
//
// A generation this build does not speak is an error rather than a best-effort
// dial: the client would otherwise discover the peer, open a stream on a protocol
// nothing is listening on, and report a libp2p-level failure that says nothing
// about the actual cause.
//
// Supporting an older generation later is one arm of this switch plus registering
// its handlers on the host - the shape is here so that stays a small change
// rather than a redesign.
func ProtocolsFor(v TokenVersion) (Protocols, error) {
	switch v {
	case TokenVersionCurrent:
		return CurrentProtocols(), nil
	case TokenVersionLegacy:
		return Protocols{}, fmt.Errorf("%w: the token carries no version, so it was produced by a pre-generation-%d build speaking /mtunnel/1.0.0; this build speaks %s and cannot reach it - upgrade the host", ErrTokenVersionUnsupported, ProtocolGeneration, ProtocolID)
	default:
		return Protocols{}, fmt.Errorf("%w: token version %d is newer than this build's %d - upgrade the client", ErrTokenVersionUnsupported, v, TokenVersionCurrent)
	}
}
