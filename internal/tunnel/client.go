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

	if opts.P2P.DHTMode == p2p.DHTCloseAfterConnect {
		if err := clientDHT.Close(); err != nil {
			p2p.Close(nil, h)
			return fmt.Errorf("close client DHT after connect: %w", err)
		}
		clientDHT = nil
		log.Println("Client DHT closed after discovery and connection")
	}
	if opts.P2P.Diagnostic {
		go p2p.StartDiagnostics(ctx, h, clientDHT, decodedToken.ID, opts.Bandwidth)
	}

	// Shut the client down if the host goes away entirely.
	watcher := newRemoteDisconnectWatcher(decodedToken.ID, requestShutdown)
	h.Network().Notify(watcher)

	opener := streamOpener{h: h, target: decodedToken.ID, config: opts.P2P}
	forwarder, err := t.Listen(ctx, opener, localPort)
	if err != nil {
		h.Network().StopNotify(watcher)
		p2p.Close(clientDHT, h)
		return fmt.Errorf("listen on local port %d: %w", localPort, err)
	}

	log.Printf("Listening for local connections on %s", forwarder.Addr)
	emitter.Emit(control.Output{
		Action:    control.CONNECTED,
		SessionId: h.ID(),
		Port:      forwarder.Port(),
	})

	var wg sync.WaitGroup
	wg.Go(forwarder.Serve)

	<-ctx.Done()
	log.Println("Initiating graceful shutdown...")

	// Stop watching, stop accepting, then close the libp2p stack (which unblocks any
	// in-flight pipes) before waiting for the forwarder to drain.
	h.Network().StopNotify(watcher)
	_ = forwarder.Close()
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
