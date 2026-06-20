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
		closeTransport(clientDHT, h)
		return fmt.Errorf("discover peer %s: %w", decodedToken.ID, err)
	}

	requestShutdown := func(reason string) {
		log.Printf("Shutdown requested: %s", reason)
		cancel()
	}
	go handleIOAction(ctx, nil, requestShutdown)

	if err := connectToPeer(ctx, h, info); err != nil {
		closeTransport(clientDHT, h)
		return fmt.Errorf("connect to peer %s: %w", decodedToken.ID, err)
	}

	// Shut the client down if the host goes away entirely.
	watcher := newRemoteDisconnectWatcher(decodedToken.ID, requestShutdown)
	h.Network().Notify(watcher)

	listen, err := net.Listen(decodedToken.Network, fmt.Sprintf("localhost:%d", localPort))
	if err != nil {
		h.Network().StopNotify(watcher)
		closeTransport(clientDHT, h)
		return fmt.Errorf("listen on local port %d: %w", localPort, err)
	}

	log.Printf("Listening for local connections on %s", listen.Addr().String())
	sendOutputAction(OutputAction{
		Action:    CONNECTED,
		SessionId: h.ID(),
		Port:      listen.Addr().(*net.TCPAddr).Port,
	})

	var wg sync.WaitGroup
	wg.Go(func() {
		acceptLocalConns(ctx, h, decodedToken.ID, listen)
	})

	<-ctx.Done()
	log.Println("Initiating graceful shutdown...")

	// Stop watching, stop accepting, then close the transport (which unblocks
	// any in-flight pipes) before waiting for the accept loop to drain.
	h.Network().StopNotify(watcher)
	listen.Close()
	closeTransport(clientDHT, h)
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

	streamCtx, cancel := context.WithTimeout(ctx, streamOpenTimeout)
	defer cancel()

	// Permit opening the stream over a limited (circuit-relay) connection.
	// Without this, libp2p refuses to open streams while the connection is
	// relay-only, so traffic would fail whenever hole punching has not yet
	// produced a direct connection - the classic "connected but no data" case.
	streamCtx = network.WithAllowLimitedConn(streamCtx, "mtunnel")

	s, err := h.NewStream(streamCtx, target, protocolID)
	if err != nil {
		log.Printf("Failed to open stream to peer %s: %v", target, err)
		return
	}
	defer s.Close()

	log.Printf("Opened stream to peer %s", target)
	pipe(s, conn)
	log.Printf("Closed stream to peer %s", target)
}
