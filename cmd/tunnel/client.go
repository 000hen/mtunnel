package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

func runClient(ctx context.Context, h host.Host, token string, localPort int) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	decodedToken, err := DecodeToken(token)
	if err != nil {
		_ = h.Close()
		return err
	}

	t, err := transportFor(decodedToken.Network)
	if err != nil {
		_ = h.Close()
		return err
	}

	// The DHT shares the client's lifetime: it is created with ctx and closed
	// during cleanup, so it stays usable for the whole discovery phase.
	clientDHT, err := setupDHT(ctx, h, false)
	if err != nil {
		_ = h.Close()
		return fmt.Errorf("bootstrap DHT: %w", err)
	}

	log.Println("Routing table size:", clientDHT.RoutingTable().Size())

	info, err := findPeerInDHT(ctx, clientDHT, decodedToken.ID)
	if err != nil {
		closeLibp2p(clientDHT, h)
		return fmt.Errorf("discover peer %s: %w", decodedToken.ID, err)
	}

	requestShutdown := func(reason string) {
		log.Printf("Shutdown requested: %s", reason)
		cancel()
	}
	go handleIOAction(ctx, nil, requestShutdown)

	if err := connectToPeer(ctx, h, info); err != nil {
		closeLibp2p(clientDHT, h)
		return fmt.Errorf("connect to peer %s: %w", decodedToken.ID, err)
	}

	// Shut the client down if the host goes away entirely.
	watcher := newRemoteDisconnectWatcher(decodedToken.ID, requestShutdown)
	h.Network().Notify(watcher)

	forwarder, err := t.listenLocal(ctx, h, decodedToken.ID, localPort)
	if err != nil {
		h.Network().StopNotify(watcher)
		closeLibp2p(clientDHT, h)
		return fmt.Errorf("listen on local port %d: %w", localPort, err)
	}

	log.Printf("Listening for local connections on %s", forwarder.addr)
	sendOutputAction(OutputAction{
		Action:    CONNECTED,
		SessionId: h.ID(),
		Port:      addrPort(forwarder.addr),
	})

	var wg sync.WaitGroup
	wg.Go(forwarder.serve)

	<-ctx.Done()
	log.Println("Initiating graceful shutdown...")

	// Stop watching, stop accepting, then close the libp2p stack (which unblocks
	// any in-flight pipes) before waiting for the forwarder to drain.
	h.Network().StopNotify(watcher)
	_ = forwarder.close()
	closeLibp2p(clientDHT, h)
	wg.Wait()

	log.Println("Shutdown completed.")

	return nil
}

// acceptLocalConns accepts connections on the local listener and forwards each
// one over a dedicated tunnel stream, returning once the listener is closed and
// all in-flight connections have finished.
func acceptLocalConns(ctx context.Context, h host.Host, target peer.ID, listen net.Listener) {
	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		localConn, err := listen.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				log.Println("Local listener closed, no longer accepting connections")
				return
			}

			log.Printf("Failed to accept local connection: %v", err)
			continue
		}

		wg.Go(func() {
			handleClientStream(ctx, h, target, localConn)
		})
	}
}

func handleClientStream(ctx context.Context, h host.Host, target peer.ID, conn net.Conn) {
	defer conn.Close()

	s, err := openTunnelStream(ctx, h, target)
	if err != nil {
		log.Printf("Failed to open stream to peer %s: %v", target, err)
		return
	}
	defer s.Close()

	log.Printf("Opened stream to peer %s", target)
	pipe(s, conn)
	log.Printf("Closed stream to peer %s", target)
}

// openTunnelStream opens a tunnel stream to the host. It permits opening over a
// limited (circuit-relay) connection: without this, libp2p refuses to open
// streams while the connection is relay-only, so traffic would fail whenever
// hole punching has not yet produced a direct connection - the classic
// "connected but no data" case.
func openTunnelStream(ctx context.Context, h host.Host, target peer.ID) (network.Stream, error) {
	streamCtx, cancel := context.WithTimeout(ctx, streamOpenTimeout)
	defer cancel()

	streamCtx = network.WithAllowLimitedConn(streamCtx, "mtunnel")
	return h.NewStream(streamCtx, target, protocolID)
}
