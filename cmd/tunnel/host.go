package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
)

func runHost(ctx context.Context, h host.Host, networkType string, forwardPort int) error {
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

	idht, err := setupDHT(ctx, h, true)
	if err != nil {
		_ = h.Close()
		return fmt.Errorf("create DHT: %w", err)
	}

	log.Println("Waiting for network stabilization...")
	waitForNetworkReady(ctx, h, networkStabilizationDelay)
	if ctx.Err() != nil {
		closeLibp2p(idht, h)
		return nil
	}

	logHostAddrs(h)

	encodedToken, err := ConnToken{Network: t.network(), ID: h.ID()}.Encode()
	if err != nil {
		closeLibp2p(idht, h)
		return err
	}
	session := NewSessionManager(h.Network())
	var wg sync.WaitGroup

	addr := fmt.Sprintf("localhost:%d", forwardPort)
	// Register the stream handler before announcing readiness so that an eager
	// client cannot connect during a window where no handler is installed.
	h.SetStreamHandler(protocolID, func(s network.Stream) {
		peer := s.Conn().RemotePeer()
		if !session.BeginStream(peer, s.Conn()) {
			// The host is shutting down and no longer serving streams.
			_ = s.Reset()
			return
		}
		defer session.EndStream(peer)

		handleHostStream(ctx, t, s, addr)
	})

	announceToken(encodedToken)

	wg.Go(func() {
		handleIOAction(ctx, session, requestShutdown)
	})

	<-ctx.Done()
	log.Println("Initiating graceful shutdown...")

	// Stop accepting new streams, then reset active ones and wait for their
	// handlers to drain (session.Shutdown) and for the IO handler to return (wg)
	// before closing the libp2p stack.
	h.RemoveStreamHandler(protocolID)
	session.Shutdown()
	wg.Wait()

	closeLibp2p(idht, h)
	log.Println("Shutdown completed.")

	return nil
}

// waitForNetworkReady blocks until the host advertises at least one dialable
// address - a public address, or a relay address that AutoRelay obtains once
// AutoNAT determines the host is behind a NAT - or until the timeout or context
// cancellation fires. Announcing only once such an address exists keeps a client
// from discovering the host in the DHT before it can actually be reached, while
// the timeout still bounds the wait when no dialable address ever appears.
func waitForNetworkReady(ctx context.Context, h host.Host, timeout time.Duration) {
	// Watch reachability and address changes together: AutoNAT determines
	// reachability, which in turn drives AutoRelay to acquire a relay address for
	// a NATed host. Either event is a cue to re-check the host's addresses.
	sub, err := h.EventBus().Subscribe([]any{
		new(event.EvtLocalReachabilityChanged),
		new(event.EvtLocalAddressesUpdated),
	})
	if err != nil {
		// Without the subscription we cannot observe the network state, so fall
		// back to the original behaviour of waiting for a fixed delay.
		log.Printf("Failed to subscribe to network events, waiting for fixed delay: %v", err)
		select {
		case <-time.After(timeout):
		case <-ctx.Done():
		}
		return
	}
	defer sub.Close()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		if hasReachableAddr(h) {
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			log.Println("No dialable address before timeout; announcing anyway")
			return
		case ev, ok := <-sub.Out():
			if !ok {
				return
			}
			// Reachability changes are logged for visibility; readiness itself is
			// re-evaluated from h.Addrs() at the top of the loop regardless of
			// which event woke us.
			if changed, isReachability := ev.(event.EvtLocalReachabilityChanged); isReachability {
				log.Printf("Network reachability: %s", changed.Reachability)
			}
		}
	}
}

// hasReachableAddr reports whether the host advertises at least one address a
// remote peer could dial: a public address, or a circuit-relay address acquired
// by AutoRelay. Private, loopback, and link-local addresses do not count.
func hasReachableAddr(h host.Host) bool {
	for _, addr := range h.Addrs() {
		if _, err := addr.ValueForProtocol(ma.P_CIRCUIT); err == nil {
			return true
		}
		if manet.IsPublicAddr(addr) {
			return true
		}
	}
	return false
}

// handleHostStream forwards a single inbound tunnel stream to the local service
// using the transport's network semantics. The dial honours ctx so a slow local
// service does not delay shutdown.
func handleHostStream(ctx context.Context, t transport, s network.Stream, addr string) {
	remote := s.Conn().RemotePeer()
	log.Println("New stream opened from:", remote)
	defer s.Close()

	dialer := net.Dialer{Timeout: defaultLocalDialTimeout}
	localConn, err := dialer.DialContext(ctx, t.network(), addr)
	if err != nil {
		log.Printf("Failed to connect to local service on %s: %v", addr, err)
		return
	}
	defer localConn.Close()

	log.Printf("Connected to local service on %s", addr)
	t.forward(s, localConn)
	log.Println("Stream closed for peer:", remote)
}

func logHostAddrs(h host.Host) {
	log.Println("Listening on addresses:")
	for _, addr := range h.Addrs() {
		log.Println(" - ", addr.String())
	}
}

func announceToken(encodedToken string) {
	log.Println("Connection Token:")
	log.Println("-------------")
	log.Println(encodedToken)
	log.Println("-------------")

	sendOutputAction(OutputAction{
		Action: TOKEN,
		Token:  encodedToken,
	})
}
