package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
)

func runHost(ctx context.Context, h host.Host, networkType string, forwardPort int) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

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
	select {
	case <-time.After(networkStabilizationDelay):
	case <-ctx.Done():
		closeTransport(idht, h)
		return nil
	}

	logHostAddrs(h)

	encodedToken, err := ConnToken{Network: networkType, ID: h.ID()}.Encode()
	if err != nil {
		closeTransport(idht, h)
		return err
	}
	announceToken(encodedToken)

	session := NewSessionManager(h.Network())
	var wg sync.WaitGroup

	// Register the stream handler before announcing readiness so that an eager
	// client cannot connect during a window where no handler is installed.
	h.SetStreamHandler(protocolID, func(s network.Stream) {
		peer := s.Conn().RemotePeer()
		session.AddSession(peer, s.Conn())
		defer session.RemoveSession(peer, false)

		handleHostStream(s, networkType, forwardPort)
	})

	wg.Add(1)
	go func() {
		defer wg.Done()
		handleIOAction(ctx, session, requestShutdown)
	}()

	<-ctx.Done()
	log.Println("Initiating graceful shutdown...")

	// Stop accepting new streams, tear down active ones, then wait for the IO
	// handler to return before closing the transport.
	h.RemoveStreamHandler(protocolID)
	session.ForceCloseAllSessions()
	wg.Wait()

	closeTransport(idht, h)
	log.Println("Shutdown completed.")

	return nil
}

// handleHostStream forwards a single inbound tunnel stream to the local service.
func handleHostStream(s network.Stream, networkType string, forwardPort int) {
	remote := s.Conn().RemotePeer()
	log.Println("New stream opened from:", remote)
	defer s.Close()

	addr := fmt.Sprintf("localhost:%d", forwardPort)
	localConn, err := net.DialTimeout(networkType, addr, defaultLocalDialTimeout)
	if err != nil {
		log.Printf("Failed to connect to local service on %s: %v", addr, err)
		return
	}
	defer localConn.Close()

	log.Printf("Connected to local service on %s", addr)
	pipe(s, localConn)
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
