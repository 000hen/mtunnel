package main

import (
	"context"
	"fmt"
	"log"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
)

func initializePeer() (host.Host, error) {
	h, err := libp2p.New(
		libp2p.EnableHolePunching(),
		libp2p.EnableAutoRelayWithStaticRelays(dht.GetDefaultBootstrapPeerAddrInfos()),
		libp2p.NATPortMap(),
		libp2p.EnableAutoNATv2(),
		libp2p.EnableNATService(),
	)
	if err != nil {
		return nil, fmt.Errorf("create libp2p host: %w", err)
	}

	log.Println("libp2p host created with ID:", h.ID())

	return h, nil
}

// closeTransport tears down the DHT and libp2p host, logging any errors. It is
// safe to call during cleanup for both host and client roles.
func closeTransport(idht *dht.IpfsDHT, h host.Host) {
	if err := idht.Close(); err != nil {
		log.Printf("Error closing DHT: %v", err)
	}
	if err := h.Close(); err != nil {
		log.Printf("Error closing libp2p host: %v", err)
	}
}

func connectToPeer(ctx context.Context, host host.Host, peer peer.AddrInfo) error {
	if err := host.Connect(ctx, peer); err != nil {
		return fmt.Errorf("connect to peer %s: %w", peer.ID, err)
	}

	log.Println("Successfully connected to peer:", peer.ID)
	log.Println("Connected with the address(es):")
	for _, conn := range host.Network().ConnsToPeer(peer.ID) {
		log.Println(" -", conn.RemoteMultiaddr().String())
	}

	return nil
}
