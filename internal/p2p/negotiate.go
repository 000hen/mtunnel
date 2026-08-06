package p2p

import (
	"context"
	"fmt"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// OpenNegotiateStream opens the tier-negotiation stream to target. Like the data
// stream (OpenStream) it explicitly permits a limited (circuit-relay) connection:
// negotiation runs once up front, before hole punching may have produced a direct
// connection, so it cannot wait on one - the same "connected but no data" trap
// stream.go guards against.
//
// The caller owns the returned stream and drives the negotiate phases over it
// (internal/negotiate consumes it as a plain io.ReadWriter, which network.Stream
// satisfies structurally, so that package needs no libp2p import).
func OpenNegotiateStream(ctx context.Context, h host.Host, target peer.ID, cfg Config) (network.Stream, error) {
	streamCtx, cancel := context.WithTimeout(ctx, streamOpenTimeout)
	defer cancel()
	streamCtx = network.WithAllowLimitedConn(streamCtx, reasonNegotiate.allowLimited())

	stream, err := h.NewStream(streamCtx, target, cfg.protocols().Negotiate)
	if err != nil {
		return nil, fmt.Errorf("open negotiate stream to %s: %w", target, err)
	}
	LogStreamPath(StreamNegotiateOpened, stream, cfg.Diagnostic)
	return stream, nil
}
