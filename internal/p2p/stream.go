package p2p

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

// streamOpenTimeout bounds how long opening a tunnel stream may take; it can
// involve dialing and upgrading the connection to the host.
const streamOpenTimeout = 30 * time.Second

// streamReason names why a stream was opened the way it was: which connection
// policy produced it, or - for the negotiate stream - that it predates any policy
// decision. It is not decoration. libp2p records it as the reason a limited
// (circuit-relay) connection was permitted, and it is the field that distinguishes
// a relay stream that was asked for from one that was fallen back to, which is the
// distinction every relay investigation starts from.
type streamReason string

const (
	reasonDirectOnly    streamReason = "direct-only"
	reasonDirectFirst   streamReason = "direct-first"
	reasonRelayFallback streamReason = "relay-fallback"
	reasonRelayOnly     streamReason = "relay-only"
	reasonNegotiate     streamReason = "negotiate"
)

// allowLimited is the tag libp2p records when a stream is permitted over a
// limited connection. Built here so the "mtunnel:" namespace exists in one place
// rather than at each call site.
func (r streamReason) allowLimited() string { return "mtunnel:" + string(r) }

// OpenStream opens a tunnel stream to target. It permits opening over a limited
// (circuit-relay) connection: without this, libp2p refuses to open streams while
// the connection is relay-only, so traffic would fail whenever hole punching has
// not yet produced a direct connection - the classic "connected but no data" case.
func OpenStream(ctx context.Context, h host.Host, target peer.ID, cfg Config) (network.Stream, error) {
	proto := cfg.protocols().Data

	switch cfg.ConnectionMode {
	case ConnectionRelayOnly:
		return openStream(ctx, h, target, proto, true, streamOpenTimeout, cfg.Diagnostic, reasonRelayOnly)
	case ConnectionDirectOnly:
		return openDirectStream(ctx, h, target, proto, streamOpenTimeout, cfg.Diagnostic, reasonDirectOnly)
	case ConnectionDirectFirst:
		timeout := cfg.DirectDialTimeout
		if timeout <= 0 {
			timeout = 15 * time.Second
		}
		stream, err := openDirectStream(ctx, h, target, proto, timeout, cfg.Diagnostic, reasonDirectFirst)
		if err == nil {
			return stream, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		log.Printf("relay fallback used for peer %s after direct attempt failed: %v", target, err)
		return openStream(ctx, h, target, proto, true, streamOpenTimeout, cfg.Diagnostic, reasonRelayFallback)
	default:
		return nil, fmt.Errorf("unsupported connection mode %q", cfg.ConnectionMode)
	}
}

func openDirectStream(ctx context.Context, h host.Host, target peer.ID, proto protocol.ID, timeout time.Duration, diagnostic bool, reason streamReason) (network.Stream, error) {
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	stream, firstErr := openStream(waitCtx, h, target, proto, false, timeout, diagnostic, reason)
	if firstErr == nil {
		return stream, nil
	}
	if hasDirectConnection(h, target) {
		return nil, firstErr
	}

	directConnected := make(chan struct{}, 1)
	notify := &network.NotifyBundle{ConnectedF: func(_ network.Network, conn network.Conn) {
		if conn.RemotePeer() == target && !conn.Stat().Limited {
			select {
			case directConnected <- struct{}{}:
			default:
			}
		}
	}}
	h.Network().Notify(notify)
	defer h.Network().StopNotify(notify)
	if hasDirectConnection(h, target) {
		directConnected <- struct{}{}
	}

	if diagnostic {
		log.Printf("waiting up to %s for a direct connection to peer %s", timeout, target)
	}
	select {
	case <-waitCtx.Done():
		return nil, fmt.Errorf("wait for direct connection to %s: %w (initial stream error: %v)", target, waitCtx.Err(), firstErr)
	case <-directConnected:
		deadline, _ := waitCtx.Deadline()
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, fmt.Errorf("wait for direct connection to %s: %w", target, context.DeadlineExceeded)
		}
		return openStream(waitCtx, h, target, proto, false, remaining, diagnostic, reason)
	}
}

func hasDirectConnection(h host.Host, target peer.ID) bool {
	for _, conn := range h.Network().ConnsToPeer(target) {
		if !conn.Stat().Limited {
			return true
		}
	}
	return false
}

func openStream(ctx context.Context, h host.Host, target peer.ID, proto protocol.ID, allowLimited bool, timeout time.Duration, diagnostic bool, reason streamReason) (network.Stream, error) {
	streamCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if allowLimited {
		streamCtx = network.WithAllowLimitedConn(streamCtx, reason.allowLimited())
	}

	stream, err := h.NewStream(streamCtx, target, proto)
	if err != nil {
		return nil, err
	}
	if !allowLimited && stream.Conn().Stat().Limited {
		_ = stream.Reset()
		return nil, fmt.Errorf("direct stream unexpectedly opened on limited connection")
	}
	LogStreamPath(StreamOpened, stream, diagnostic)
	return stream, nil
}
