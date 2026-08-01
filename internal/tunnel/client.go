package tunnel

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"

	"mtunnel-libp2p/internal/control"
	"mtunnel-libp2p/internal/p2p"
	"mtunnel-libp2p/internal/transport"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
)

// RunClient runs the client role: it discovers the host named by token, opens a
// local listener on localPort, and forwards its traffic to the host over tunnel
// streams. It returns when ctx is cancelled and shutdown completes. RunClient takes
// ownership of h and closes it before returning.
func RunClient(ctx context.Context, h host.Host, emitter *control.Emitter, token string, localPort int, opts Options) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	decodedToken, err := p2p.DecodeToken(token)
	if err != nil {
		_ = h.Close()
		return err
	}

	t, err := transportFor(decodedToken.Network, opts.P2P.Diagnostic)
	if err != nil {
		_ = h.Close()
		return err
	}

	// The DHT shares the client's lifetime: it is created with ctx and closed during
	// cleanup, so it stays usable for the whole discovery phase.
	clientDHT, err := p2p.NewDHT(ctx, h, false, opts.P2P.DHTMode)
	if err != nil {
		_ = h.Close()
		return fmt.Errorf("bootstrap DHT: %w", err)
	}

	log.Println("Routing table size:", clientDHT.RoutingTable().Size())

	info, err := p2p.FindPeer(ctx, clientDHT, decodedToken.ID)
	if err != nil {
		p2p.Close(clientDHT, h)
		return fmt.Errorf("discover peer %s: %w", decodedToken.ID, err)
	}

	requestShutdown := func(reason string) {
		log.Printf("Shutdown requested: %s", reason)
		cancel()
	}
	go control.Handle(ctx, os.Stdin, emitter, nil, requestShutdown)

	if err := p2p.Connect(ctx, h, info, opts.P2P); err != nil {
		p2p.Close(clientDHT, h)
		return fmt.Errorf("connect to peer %s: %w", decodedToken.ID, err)
	}

	// Fresh tier credentials per run - a WireGuard keypair and a QUIC leaf - matching
	// the host's and the libp2p peer identity's; nothing here is persisted. Generated
	// before negotiation because the client advertises both in the opening exchange:
	// the WireGuard public key in Hello, the certificate fingerprint in PunchInfo.
	ids, err := newTierIdentities()
	if err != nil {
		p2p.Close(clientDHT, h)
		return err
	}

	// Negotiate the tunnel tier once per session, immediately after connecting and
	// before any forwarded connection can open a data stream, then climb the fallback
	// ladder to whatever will actually carry traffic. In auto mode this is
	// best-effort and cannot fail the session - the libp2p floor always works - but a
	// forced -tunnel-mode returns the error instead of being rescued by it. See
	// negotiateTierClient.
	//
	// wg is declared here rather than beside the forwarder because negotiation may
	// leave a background NAT punch probe running, and shutdown has to wait for it.
	var wg sync.WaitGroup
	tier, err := negotiateTierClient(ctx, h, decodedToken.ID, opts, ids, decodedToken.WireGuardPubKey, t.Network(), &wg)
	if err != nil {
		cancel()
		p2p.Close(clientDHT, h)
		wg.Wait()
		return err
	}

	if opts.P2P.DHTMode == p2p.DHTCloseAfterConnect {
		if err := clientDHT.Close(); err != nil {
			// cancel before waiting: the background punch probe launched above is
			// still running on ctx, and without this the wait would last until its
			// own timeouts expire rather than until it notices the abort.
			cancel()
			_ = tier.close()
			p2p.Close(nil, h)
			wg.Wait()
			return fmt.Errorf("close client DHT after connect: %w", err)
		}
		clientDHT = nil
		log.Println("Client DHT closed after discovery and connection")
	}
	if opts.P2P.Diagnostic {
		// The client's tier is resolved for the whole session by the time diagnostics
		// start, so unlike the host's this reporter is a constant.
		go p2p.StartDiagnostics(ctx, h, clientDHT, decodedToken.ID, opts.Bandwidth, func() string {
			return string(tier.tier)
		})
	}

	// Shut the client down if the host goes away entirely.
	watcher := newRemoteDisconnectWatcher(decodedToken.ID, requestShutdown)
	h.Network().Notify(watcher)

	// A tier above the floor brings its own opener; on the floor there is nothing to
	// substitute and forwarded connections ride libp2p streams exactly as before.
	var opener transport.Opener = streamOpener{h: h, target: decodedToken.ID, config: opts.P2P}
	if tier.opener != nil {
		opener = tier.opener
	}
	forwarder, err := t.Listen(ctx, opener, localPort)
	if err != nil {
		h.Network().StopNotify(watcher)
		cancel() // as above: abort the background probe before waiting on it
		_ = tier.close()
		p2p.Close(clientDHT, h)
		wg.Wait()
		return fmt.Errorf("listen on local port %d: %w", localPort, err)
	}

	log.Printf("Listening for local connections on %s", forwarder.Addr)
	emitter.Emit(control.Output{
		Action:    control.CONNECTED,
		SessionId: h.ID(),
		Port:      forwarder.Port(),
		Tier:      string(tier.tier),
	})

	wg.Go(forwarder.Serve)

	<-ctx.Done()
	log.Println("Initiating graceful shutdown...")

	// Stop watching, stop accepting, tear the tier down, then close the libp2p stack,
	// before waiting for the forwarder to drain.
	//
	// The tier teardown sits between the two deliberately. Closing the libp2p stack
	// unblocks in-flight pipes on the libp2p floor and nothing else; a tier above it
	// has its own substrate to release, and a pipe still riding that substrate would
	// keep the wait below going forever. On the floor this step is a no-op, so the
	// shape stays the same whichever tier won.
	h.Network().StopNotify(watcher)
	_ = forwarder.Close()
	_ = tier.close()
	p2p.Close(clientDHT, h)
	wg.Wait()

	log.Println("Shutdown completed.")

	return nil
}

// streamOpener adapts a libp2p host and target peer to transport.Opener, so the
// TCP and UDP forwarders can open tunnel streams without importing libp2p.
type streamOpener struct {
	h      host.Host
	target peer.ID
	config p2p.Config
}

// OpenStream opens a new tunnel stream to the target host.
func (o streamOpener) OpenStream(ctx context.Context) (transport.Stream, error) {
	return p2p.OpenStream(ctx, o.h, o.target, o.config)
}
