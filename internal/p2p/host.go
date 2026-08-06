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
	"github.com/libp2p/go-libp2p/core/metrics"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/host/autorelay"
	libp2pquic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	libp2ptcp "github.com/libp2p/go-libp2p/p2p/transport/tcp"
	libp2pwebrtc "github.com/libp2p/go-libp2p/p2p/transport/webrtc"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
)

// hostRole names which of the two roles a libp2p host was built for. The roles
// differ in the libp2p services they run - a server takes relay reservations and
// advertises itself, a client only dials - so the value is a policy input, not
// just a log label.
type hostRole string

const (
	roleServer hostRole = "server"
	roleClient hostRole = "client"
)

// NewServerHost creates the public-facing role. It obtains at most one relay
// reservation, while retaining hole punching and NAT reachability services.
func NewServerHost(cfg Config) (host.Host, *metrics.BandwidthCounter, error) {
	relays, err := relayCandidates(cfg.RelayAddrs)
	if err != nil {
		return nil, nil, err
	}
	opts := []libp2p.Option{
		libp2p.EnableAutoRelayWithStaticRelays(
			relays,
			autorelay.WithNumRelays(1),
		),
		libp2p.NATPortMap(),
		libp2p.EnableAutoNATv2(),
		libp2p.EnableNATService(),
	}
	if cfg.ConnectionMode != ConnectionRelayOnly {
		opts = append(opts, libp2p.EnableHolePunching())
	}
	return newHost(roleServer, cfg, opts)
}

func relayCandidates(configured []string) ([]peer.AddrInfo, error) {
	if len(configured) == 0 {
		defaults := dht.GetDefaultBootstrapPeerAddrInfos()
		const maxDefaultCandidates = 3
		if len(defaults) > maxDefaultCandidates {
			defaults = defaults[:maxDefaultCandidates]
		}
		return defaults, nil
	}

	relays := make([]peer.AddrInfo, 0, len(configured))
	for _, value := range configured {
		addr, err := ma.NewMultiaddr(value)
		if err != nil {
			return nil, fmt.Errorf("parse relay multiaddress %q: %w", value, err)
		}
		info, err := peer.AddrInfoFromP2pAddr(addr)
		if err != nil {
			return nil, fmt.Errorf("relay multiaddress %q must end in /p2p/<peer-id>: %w", value, err)
		}
		relays = append(relays, *info)
	}
	return relays, nil
}

// NewClientHost creates a dial-only role. It deliberately does not run
// AutoRelay, AutoNAT, or a NAT service: clients can still dial a server's relay
// address, but do not acquire relay reservations or advertise themselves.
func NewClientHost(cfg Config) (host.Host, *metrics.BandwidthCounter, error) {
	opts := []libp2p.Option{libp2p.NATPortMap()}
	if cfg.ConnectionMode != ConnectionRelayOnly {
		opts = append(opts, libp2p.EnableHolePunching())
	}
	return newHost(roleClient, cfg, opts)
}

func newHost(role hostRole, cfg Config, opts []libp2p.Option) (host.Host, *metrics.BandwidthCounter, error) {
	bandwidth := metrics.NewBandwidthCounter()
	opts = append(opts, libp2p.BandwidthReporter(bandwidth))

	transportOpts, err := transportOptions(cfg.Transport)
	if err != nil {
		return nil, nil, err
	}
	opts = append(opts, transportOpts...)

	h, err := libp2p.New(opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("create %s libp2p host: %w", role, err)
	}

	log.Printf("libp2p %s host created with ID %s (transport=%s)", role, h.ID(), cfg.Transport)

	return h, bandwidth, nil
}

func transportOptions(mode TransportMode) ([]libp2p.Option, error) {
	switch mode {
	case TransportDefault:
		return nil, nil
	case TransportQUIC:
		return []libp2p.Option{
			libp2p.NoTransports,
			libp2p.Transport(libp2pquic.NewTransport),
			libp2p.ListenAddrStrings("/ip4/0.0.0.0/udp/0/quic-v1", "/ip6/::/udp/0/quic-v1"),
		}, nil
	case TransportTCP:
		return []libp2p.Option{
			libp2p.NoTransports,
			libp2p.Transport(libp2ptcp.NewTCPTransport),
			libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/0", "/ip6/::/tcp/0"),
		}, nil
	case TransportWebRTC:
		return []libp2p.Option{
			libp2p.NoTransports,
			// TCP is retained for public DHT discovery. Target addresses are
			// filtered to WebRTC Direct by Connect, so tunnel streams still use
			// the selected application transport.
			libp2p.Transport(libp2ptcp.NewTCPTransport),
			libp2p.Transport(libp2pwebrtc.New),
			libp2p.ListenAddrStrings(
				"/ip4/0.0.0.0/tcp/0", "/ip6/::/tcp/0",
				"/ip4/0.0.0.0/udp/0/webrtc-direct", "/ip6/::/udp/0/webrtc-direct",
			),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported transport %q", mode)
	}
}

// Close tears down the DHT and libp2p host, logging any errors. It is safe to call
// during cleanup for both host and client roles.
func Close(idht *dht.IpfsDHT, h host.Host) {
	if idht != nil {
		if err := idht.Close(); err != nil {
			log.Printf("Error closing DHT: %v", err)
		}
	}
	if err := h.Close(); err != nil {
		log.Printf("Error closing libp2p host: %v", err)
	}
}

// Connect dials info and logs the addresses the connection was established on.
func Connect(ctx context.Context, h host.Host, info peer.AddrInfo, cfg Config) error {
	info, err := selectAddresses(info, cfg.ConnectionMode, cfg.Transport)
	if err != nil {
		return err
	}
	if cfg.Transport == TransportWebRTC && cfg.ConnectionMode != ConnectionRelayOnly {
		// FindPeer may have reached the target over the TCP transport retained for
		// DHT discovery. Host.Connect is a no-op while any target connection exists,
		// so remove those mismatched connections before dialing the filtered
		// WebRTC Direct address.
		for _, conn := range h.Network().ConnsToPeer(info.ID) {
			if _, err := conn.RemoteMultiaddr().ValueForProtocol(ma.P_WEBRTC_DIRECT); err != nil {
				log.Printf("Closing non-WebRTC discovery connection %s to target %s", conn.ID(), info.ID)
				if err := conn.Close(); err != nil {
					log.Printf("Failed to close discovery connection %s: %v", conn.ID(), err)
				}
			}
		}
	}
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

func selectAddresses(info peer.AddrInfo, connectionMode ConnectionMode, transportMode TransportMode) (peer.AddrInfo, error) {
	filtered := info
	filtered.Addrs = make([]ma.Multiaddr, 0, len(info.Addrs))
	for _, addr := range info.Addrs {
		_, circuitErr := addr.ValueForProtocol(ma.P_CIRCUIT)
		isCircuit := circuitErr == nil
		if connectionMode == ConnectionRelayOnly {
			if isCircuit {
				filtered.Addrs = append(filtered.Addrs, addr)
			}
			continue
		}

		switch transportMode {
		case TransportDefault:
			filtered.Addrs = append(filtered.Addrs, addr)
		case TransportQUIC:
			if _, err := addr.ValueForProtocol(ma.P_QUIC_V1); err == nil {
				filtered.Addrs = append(filtered.Addrs, addr)
			}
		case TransportTCP:
			if _, err := addr.ValueForProtocol(ma.P_TCP); err == nil && !isCircuit {
				filtered.Addrs = append(filtered.Addrs, addr)
			}
		case TransportWebRTC:
			if _, err := addr.ValueForProtocol(ma.P_WEBRTC_DIRECT); err == nil {
				filtered.Addrs = append(filtered.Addrs, addr)
			}
		}
	}
	if len(filtered.Addrs) == 0 {
		return peer.AddrInfo{}, fmt.Errorf("peer %s advertised no address matching connection=%s transport=%s", info.ID, connectionMode, transportMode)
	}
	return filtered, nil
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
