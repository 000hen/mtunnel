package tunnel

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"sync"

	"mtunnel-libp2p/internal/control"
	"mtunnel-libp2p/internal/p2p"
	"mtunnel-libp2p/internal/transport"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// RunHost runs the host role: it announces a connection token over the DHT and
// forwards each inbound tunnel stream to the local service on forwardPort. It
// returns when ctx is cancelled and shutdown completes. RunHost takes ownership of
// h and closes it before returning.
func RunHost(ctx context.Context, h host.Host, emitter *control.Emitter, networkType transport.Network, forwardPort int, opts Options) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	t, err := transportFor(networkType, opts.P2P.Diagnostic)
	if err != nil {
		_ = h.Close()
		return err
	}

	requestShutdown := func(reason string) {
		log.Printf("Shutdown requested: %s", reason)
		cancel()
	}

	idht, err := p2p.NewDHT(ctx, h, true, opts.P2P.DHTMode)
	if err != nil {
		_ = h.Close()
		return fmt.Errorf("create DHT: %w", err)
	}

	log.Println("Waiting for network stabilization...")
	p2p.WaitForNetworkReady(ctx, h, networkStabilizationDelay)
	if ctx.Err() != nil {
		p2p.Close(idht, h)
		return nil
	}

	p2p.LogAddrs(h)

	// Build this run's data plane - the tier registry and the credentials it serves
	// with - and publish the WireGuard public key in the token. Like the libp2p peer
	// identity, none of it is persisted.
	ts, err := newTiers(opts)
	if err != nil {
		p2p.Close(idht, h)
		return err
	}

	// The token carries no version field of its own to fill in: Token.Encode stamps
	// the current one, which is what tells an older client to stop rather than to
	// speak a protocol this build no longer serves.
	encodedToken, err := p2p.Token{
		Network:         t.Network(),
		ID:              h.ID(),
		WireGuardPubKey: ts.ids.WireGuardPublicKey(),
	}.Encode()
	if err != nil {
		p2p.Close(idht, h)
		return err
	}
	session := NewSessionManager(h.Network(), emitter)
	var wg sync.WaitGroup

	addr := fmt.Sprintf("localhost:%d", forwardPort)
	// The libp2p data handler is the tunnel's floor, and it stays registered even
	// when a client negotiates a tier above it: the host serves whichever data plane
	// the client actually uses, so a client that gave up on WireGuard is already
	// served with no second round of agreement about the failure.
	//
	// Forcing a specific tier (-tunnel-mode=wireguard or =quic) is the one case that
	// leaves it unregistered. The point of forcing a tier is to learn whether it
	// works, which a silent rescue by the floor would hide - so a client that falls
	// back finds nothing listening and fails loudly.
	if !forcesTier(opts.P2P.TunnelMode) {
		// Registered before announcing readiness so that an eager client cannot
		// connect during a window where no handler is installed.
		h.SetStreamHandler(p2p.ProtocolID, func(s network.Stream) {
			p2p.LogStreamPath(p2p.StreamAccepted, s, opts.P2P.Diagnostic)
			remote := s.Conn().RemotePeer()
			if !session.BeginStream(remote, s.Conn()) {
				// The host is shutting down and no longer serving streams.
				_ = s.Reset()
				return
			}
			defer session.EndStream(remote)

			handleHostStream(ctx, t, s, remote, addr)
		})
	}

	// Register the tier-negotiation handler alongside the data handler, also before
	// announcing readiness. This is where a session's data plane is decided, and for
	// a tier above the floor it is also where that tier lives: the handler holds the
	// negotiate stream open and serves the tunnel for as long as the peer is there.
	//
	// Negotiation handlers are tracked separately from data streams: they hold no
	// session and emit no CONNECTED event of their own, but they far outlive the
	// exchange itself, so shutdown has to wait for them rather than close the libp2p
	// stack out from under them.
	var negotiations handlerGroup
	deps := hostTierDeps{tiers: ts, session: session, transport: t, localAddr: addr}
	h.SetStreamHandler(p2p.NegotiateProtocolID, func(s network.Stream) {
		if !negotiations.begin() {
			// Shutting down and no longer negotiating.
			_ = s.Reset()
			return
		}
		defer negotiations.done()

		negotiateTierHost(ctx, opts, deps, s)
	})

	announceToken(emitter, encodedToken)
	if opts.P2P.Diagnostic {
		go p2p.StartDiagnostics(ctx, h, idht, "", opts.Bandwidth, session.ActiveTier)
	}

	wg.Go(func() {
		control.Handle(ctx, os.Stdin, emitter, session, requestShutdown)
	})

	<-ctx.Done()
	log.Println("Initiating graceful shutdown...")

	// Stop accepting new streams and new negotiations, then retire every tier and
	// wait for the forwarded connections riding them to drain (session.Shutdown),
	// then for the negotiation handlers that own those tiers to unwind
	// (negotiations.shutdown - ctx is already cancelled, so these are unwinding
	// rather than running to completion), and for the control handler to return (wg),
	// before closing the libp2p stack.
	//
	// session.Shutdown has to come before negotiations.shutdown, not after: a
	// negotiation handler serving a WireGuard tier does not return until the
	// forwarded connections on it are done, and only session.Shutdown releases them.
	h.RemoveStreamHandler(p2p.ProtocolID)
	h.RemoveStreamHandler(p2p.NegotiateProtocolID)
	session.Shutdown()
	negotiations.shutdown()
	wg.Wait()

	p2p.Close(idht, h)
	log.Println("Shutdown completed.")

	return nil
}

// handleHostStream forwards a single inbound tunnel stream to the local service
// using the transport's network semantics. The dial honours ctx so a slow local
// service does not delay shutdown.
//
// It takes transport.Stream rather than network.Stream so every tier shares it: a
// WireGuard virtual connection arrives here through transport.ConnStream and is
// forwarded identically. remote is passed in for the same reason - only a libp2p
// stream can name its own peer.
func handleHostStream(ctx context.Context, t transport.Transport, s transport.Stream, remote peer.ID, addr string) {
	log.Println("New stream opened from:", remote)
	defer s.Close()

	dialer := net.Dialer{Timeout: defaultLocalDialTimeout}
	// transport.Network's underlying string is the net package's network name, which
	// is why it is a named string rather than an integer - see transport.Network.
	localConn, err := dialer.DialContext(ctx, string(t.Network()), addr)
	if err != nil {
		log.Printf("Failed to connect to local service on %s: %v", addr, err)
		return
	}
	defer localConn.Close()

	log.Printf("Connected to local service on %s", addr)
	t.Forward(s, localConn)
	log.Println("Stream closed for peer:", remote)
}

// announceToken logs the connection token and emits it as a TOKEN event for
// automation.
func announceToken(emitter *control.Emitter, encodedToken string) {
	log.Println("Connection Token:")
	log.Println("-------------")
	log.Println(encodedToken)
	log.Println("-------------")

	emitter.Emit(control.Output{
		Action: control.TOKEN,
		Token:  encodedToken,
	})
}
