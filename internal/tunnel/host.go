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
)

// RunHost runs the host role: it announces a connection token over the DHT and
// forwards each inbound tunnel stream to the local service on forwardPort. It
// returns when ctx is cancelled and shutdown completes. RunHost takes ownership of
// h and closes it before returning.
func RunHost(ctx context.Context, h host.Host, emitter *control.Emitter, networkType string, forwardPort int) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	t, err := transportFor(networkType)
	if err != nil {
		_ = h.Close()
		return err
	}

	requestShutdown := func(reason string) {
		log.Printf("Shutdown requested: %s", reason)
		cancel()
	}

	idht, err := p2p.NewDHT(ctx, h, true)
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

	encodedToken, err := p2p.Token{Network: t.Network(), ID: h.ID()}.Encode()
	if err != nil {
		p2p.Close(idht, h)
		return err
	}
	session := NewSessionManager(h.Network(), emitter)
	var wg sync.WaitGroup

	addr := fmt.Sprintf("localhost:%d", forwardPort)
	// Register the stream handler before announcing readiness so that an eager
	// client cannot connect during a window where no handler is installed.
	h.SetStreamHandler(p2p.ProtocolID, func(s network.Stream) {
		remote := s.Conn().RemotePeer()
		if !session.BeginStream(remote, s.Conn()) {
			// The host is shutting down and no longer serving streams.
			_ = s.Reset()
			return
		}
		defer session.EndStream(remote)

		handleHostStream(ctx, t, s, addr)
	})

	announceToken(emitter, encodedToken)

	wg.Go(func() {
		control.Handle(ctx, os.Stdin, emitter, session, requestShutdown)
	})

	<-ctx.Done()
	log.Println("Initiating graceful shutdown...")

	// Stop accepting new streams, then reset active ones and wait for their handlers
	// to drain (session.Shutdown) and for the control handler to return (wg) before
	// closing the libp2p stack.
	h.RemoveStreamHandler(p2p.ProtocolID)
	session.Shutdown()
	wg.Wait()

	p2p.Close(idht, h)
	log.Println("Shutdown completed.")

	return nil
}

// handleHostStream forwards a single inbound tunnel stream to the local service
// using the transport's network semantics. The dial honours ctx so a slow local
// service does not delay shutdown.
func handleHostStream(ctx context.Context, t transport.Transport, s network.Stream, addr string) {
	remote := s.Conn().RemotePeer()
	log.Println("New stream opened from:", remote)
	defer s.Close()

	dialer := net.Dialer{Timeout: defaultLocalDialTimeout}
	localConn, err := dialer.DialContext(ctx, t.Network(), addr)
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
