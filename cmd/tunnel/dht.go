package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/routing"
)

func setupDHT(ctx context.Context, h host.Host, asServer bool) (*dht.IpfsDHT, error) {
	mode := dht.ModeClient
	if asServer {
		mode = dht.ModeAutoServer
	}

	dhtInstance, err := dht.New(ctx, h, dht.Mode(mode))
	if err != nil {
		return nil, err
	}

	if err := dhtInstance.Bootstrap(ctx); err != nil {
		_ = dhtInstance.Close()
		return nil, err
	}

	if err := connectToBootstrapPeers(ctx, h); err != nil {
		log.Printf("Bootstrap peer connection failed: %v", err)
	}

	return dhtInstance, nil
}

func connectToBootstrapPeers(ctx context.Context, h host.Host) error {
	for _, addr := range dht.GetDefaultBootstrapPeerAddrInfos() {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := h.Connect(dialCtx, addr)
		cancel()

		if err != nil {
			log.Printf("Failed to connect to bootstrap peer %s: %v", addr.ID, err)
		} else {
			log.Printf("Connected to bootstrap peer: %s", addr.ID)
		}
	}

	return nil
}

// findPeerInDHT looks up a peer's addresses in the DHT. The host's record may
// not have propagated yet when the client starts, so the lookup is retried with
// a bounded per-attempt timeout instead of failing fatally on the first miss.
func findPeerInDHT(ctx context.Context, dhtInstance *dht.IpfsDHT, peerID peer.ID) (peer.AddrInfo, error) {
	var lastErr error

	for attempt := 1; attempt <= dhtLookupMaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return peer.AddrInfo{}, err
		}

		lookupCtx, cancel := context.WithTimeout(ctx, dhtLookupTimeout)
		info, findErr := dhtInstance.FindPeer(lookupCtx, peerID)
		cancel()

		if findErr == nil && len(info.Addrs) > 0 {
			log.Printf("Discovered peer %s via DHT with %d addresses", info.ID, len(info.Addrs))
			log.Println("Addresses found via DHT:")
			for _, a := range info.Addrs {
				log.Println(" -", a.String())
			}
			return info, nil
		}

		if findErr == nil {
			lastErr = fmt.Errorf("peer %s found but no addresses available", peerID)
		} else if errors.Is(findErr, routing.ErrNotFound) {
			lastErr = fmt.Errorf("peer %s not yet available in DHT", peerID)
		} else {
			lastErr = fmt.Errorf("DHT lookup for peer %s failed: %w", peerID, findErr)
		}

		log.Printf("Peer discovery attempt %d/%d failed: %v", attempt, dhtLookupMaxAttempts, lastErr)

		if attempt < dhtLookupMaxAttempts {
			select {
			case <-ctx.Done():
				return peer.AddrInfo{}, ctx.Err()
			case <-time.After(dhtLookupRetryDelay):
			}
		}
	}

	return peer.AddrInfo{}, lastErr
}
