package p2p

import (
	"context"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// streamOpenTimeout bounds how long opening a tunnel stream may take; it can
// involve dialing and upgrading the connection to the host.
const streamOpenTimeout = 30 * time.Second

// OpenStream opens a tunnel stream to target. It permits opening over a limited
// (circuit-relay) connection: without this, libp2p refuses to open streams while
// the connection is relay-only, so traffic would fail whenever hole punching has
// not yet produced a direct connection - the classic "connected but no data" case.
func OpenStream(ctx context.Context, h host.Host, target peer.ID) (network.Stream, error) {
	streamCtx, cancel := context.WithTimeout(ctx, streamOpenTimeout)
	defer cancel()

	streamCtx = network.WithAllowLimitedConn(streamCtx, "mtunnel")
	return h.NewStream(streamCtx, target, ProtocolID)
}
