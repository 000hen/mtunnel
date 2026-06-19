package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

func runClient(host host.Host, token string, localPort int) {
	var decodedToken ConnToken

	// Decode the connection token
	data, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		log.Fatalf("Failed to decode token: %v", err)
	}

	if err := gob.NewDecoder(bytes.NewBuffer(data)).Decode(&decodedToken); err != nil {
		log.Fatalf("Failed to decode token data: %v", err)
	}

	// Setup DHT for peer discovery
	dhtCtx, dhtCancel := context.WithCancel(context.Background())
	clientDHT, err := setupDHT(dhtCtx, host, false)
	if err != nil {
		dhtCancel()
		_ = host.Close()
		log.Fatalf("Failed to bootstrap DHT: %v", err)
	}

	log.Println("Routing table size:", clientDHT.RoutingTable().Size())
	info, err := findPeerInDHT(dhtCtx, clientDHT, decodedToken.ID)
	if err != nil {
		dhtCancel()
		sendOutputAction(OutputAction{
			Action: ERROR,
			Error:  fmt.Sprintf("Failed to discover peer %s: %v", decodedToken.ID, err),
		})
		_ = clientDHT.Close()
		_ = host.Close()
		log.Fatalf("Failed to discover peer %s: %v", decodedToken.ID, err)
	}
	dhtCancel()

	var remoteWatcher network.Notifiee

	// cleanup
	var cleanupOnce sync.Once
	cleanupTransport := func() {
		cleanupOnce.Do(func() {
			if remoteWatcher != nil {
				host.Network().StopNotify(remoteWatcher)
			}
			if err := clientDHT.Close(); err != nil {
				log.Printf("Error closing DHT: %v", err)
			}
			if err := host.Close(); err != nil {
				log.Printf("Error closing libp2p host: %v", err)
			}
		})
	}

	shutdownChan := make(chan string, 1)
	requestShutdown := func(reason string) {
		if reason == "" {
			reason = "stdin shutdown request"
		}
		select {
		case shutdownChan <- reason:
		default:
		}
	}

	// Connect to the discovered peer
	ctx, cancel := context.WithCancel(context.Background())
	go handleIOAction(ctx, nil, requestShutdown)
	if err := connectToPeer(ctx, host, info); err != nil {
		sendOutputAction(OutputAction{
			Action: ERROR,
			Error:  fmt.Sprintf("Failed to connect to peer %s: %v", decodedToken.ID, err),
		})
		cleanupTransport()
		log.Fatalf("Failed to connect to peer %s: %v", decodedToken.ID, err)
	}

	remoteWatcher = newRemoteDisconnectWatcher(decodedToken.ID, requestShutdown)
	host.Network().Notify(remoteWatcher)

	// Start listening on the local port
	listen, err := net.Listen(decodedToken.Network, fmt.Sprintf("localhost:%d", localPort))
	if err != nil {
		cleanupTransport()
		log.Fatalf("Failed to listen on local port %d: %v", localPort, err)
	}

	log.Printf("Listening for local connections on %s", listen.Addr().String())

	port := listen.Addr().(*net.TCPAddr).Port
	sendOutputAction(OutputAction{
		Action:    CONNECTED,
		SessionId: host.ID(),
		Port:      port,
	})

	var wg sync.WaitGroup
	go func(listen net.Listener) {
		for {
			localConn, err := listen.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					log.Println("Local listener closed, exiting...")
					return
				}

				log.Printf("Failed to accept local connection: %v", err)
				continue
			}

			wg.Add(1)
			go func(conn net.Conn) {
				defer wg.Done()
				handleClientStream(ctx, host, decodedToken.ID, conn)
			}(localConn)
		}
	}(listen)

	// Handle graceful shutdown on interrupt signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	var shutdownReason string
	select {
	case sig := <-sigChan:
		shutdownReason = fmt.Sprintf("signal: %v", sig)
	case reason := <-shutdownChan:
		shutdownReason = reason
	}

	if shutdownReason == "" {
		shutdownReason = "shutdown requested"
	}
	log.Printf("Received shutdown trigger (%s)", shutdownReason)
	log.Println("Initiating graceful shutdown...")

	cancel()
	listen.Close()

	log.Println("Waiting for active streams...")
	wg.Wait()
	cleanupTransport()

	log.Println("Shutdown completed.")
}

func handleClientStream(ctx context.Context, host host.Host, peer peer.ID, conn net.Conn) {
	streamCtx, streamCancel := context.WithTimeout(ctx, 30*time.Second)
	defer streamCancel()

	// Permit opening the stream over a limited (circuit-relay) connection.
	// Without this, libp2p refuses to open streams while the connection is
	// relay-only, so traffic would fail whenever hole punching has not yet
	// produced a direct connection - the classic "connected but no data" case.
	streamCtx = network.WithAllowLimitedConn(streamCtx, "mtunnel")

	s, err := host.NewStream(streamCtx, peer, protocolID)
	if err != nil {
		log.Printf("Failed to open stream to peer %s: %v", peer, err)
		if closeErr := conn.Close(); closeErr != nil {
			log.Printf("Error closing local connection: %v", closeErr)
		}
		return
	}
	defer s.Close()

	log.Printf("Opened stream to peer %s", peer)
	pipe(s, conn)
	log.Printf("Closed stream to peer %s", peer)
}
