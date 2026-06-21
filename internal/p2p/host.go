// Package p2p wraps the libp2p host, DHT discovery, connection tokens, and tunnel
// stream setup. It is the tunnel's only point of contact with libp2p.
package p2p

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
)

// ProtocolID identifies the tunnel stream protocol spoken between host and client.
const ProtocolID = "/mtunnel/1.0.0"

// New creates a libp2p host configured for NAT traversal: hole punching, AutoRelay
// with the default bootstrap peers as static relays, NAT port mapping, and the
// AutoNATv2 and NAT services.
func New() (host.Host, error) {
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

// Close tears down the DHT and libp2p host, logging any errors. It is safe to call
// during cleanup for both host and client roles.
func Close(idht *dht.IpfsDHT, h host.Host) {
	if err := idht.Close(); err != nil {
		log.Printf("Error closing DHT: %v", err)
	}
	if err := h.Close(); err != nil {
		log.Printf("Error closing libp2p host: %v", err)
	}
}

// Connect dials info and logs the addresses the connection was established on.
func Connect(ctx context.Context, h host.Host, info peer.AddrInfo) error {
	if err := h.Connect(ctx, info); err != nil {
		return fmt.Errorf("connect to peer %s: %w", info.ID, err)
	}

	log.Println("Successfully connected to peer:", info.ID)
	log.Println("Connected with the address(es):")
	for _, conn := range h.Network().ConnsToPeer(info.ID) {
		log.Println(" -", conn.RemoteMultiaddr().String())
	}

	return nil
}

// WaitForNetworkReady blocks until the host advertises at least one dialable
// address - a public address, or a relay address that AutoRelay obtains once
// AutoNAT determines the host is behind a NAT - or until the timeout or context
// cancellation fires. Announcing only once such an address exists keeps a client
// from discovering the host in the DHT before it can actually be reached, while
// the timeout still bounds the wait when no dialable address ever appears.
func WaitForNetworkReady(ctx context.Context, h host.Host, timeout time.Duration) {
	// Watch reachability and address changes together: AutoNAT determines
	// reachability, which in turn drives AutoRelay to acquire a relay address for a
	// NATed host. Either event is a cue to re-check the host's addresses.
	sub, err := h.EventBus().Subscribe([]any{
		new(event.EvtLocalReachabilityChanged),
		new(event.EvtLocalAddressesUpdated),
	})
	if err != nil {
		// Without the subscription we cannot observe the network state, so fall back
		// to the original behaviour of waiting for a fixed delay.
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
			// re-evaluated from h.Addrs() at the top of the loop regardless of which
			// event woke us.
			if changed, isReachability := ev.(event.EvtLocalReachabilityChanged); isReachability {
				log.Printf("Network reachability: %s", changed.Reachability)
			}
		}
	}
}

// hasReachableAddr reports whether the host advertises at least one address a
// remote peer could dial: a public address, or a circuit-relay address acquired by
// AutoRelay. Private, loopback, and link-local addresses do not count.
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

// LogAddrs logs the host's current listen addresses.
func LogAddrs(h host.Host) {
	log.Println("Listening on addresses:")
	for _, addr := range h.Addrs() {
		log.Println(" - ", addr.String())
	}
}
