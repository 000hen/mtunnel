package p2p

import (
	"fmt"
	"strings"
	"time"
)

// ConnectionMode controls whether tunnel streams may use circuit-relay
// connections. A stream stays on the connection on which it was opened, so this
// policy is applied before every stream is created.
type ConnectionMode string

const (
	ConnectionDirectOnly  ConnectionMode = "direct-only"
	ConnectionDirectFirst ConnectionMode = "direct-first"
	ConnectionRelayOnly   ConnectionMode = "relay-only"
)

func ParseConnectionMode(value string) (ConnectionMode, error) {
	mode := ConnectionMode(strings.ToLower(value))
	switch mode {
	case ConnectionDirectOnly, ConnectionDirectFirst, ConnectionRelayOnly:
		return mode, nil
	default:
		return "", fmt.Errorf("unsupported connection mode %q (want direct-only, direct-first, or relay-only)", value)
	}
}

// TransportMode selects the libp2p transport set used for controlled A/B tests.
type TransportMode string

const (
	TransportDefault TransportMode = "default"
	TransportQUIC    TransportMode = "quic"
	TransportTCP     TransportMode = "tcp"
	TransportWebRTC  TransportMode = "webrtc"
)

func ParseTransportMode(value string) (TransportMode, error) {
	mode := TransportMode(strings.ToLower(value))
	switch mode {
	case TransportDefault, TransportQUIC, TransportTCP, TransportWebRTC:
		return mode, nil
	default:
		return "", fmt.Errorf("unsupported transport %q (want default, quic, tcp, or webrtc)", value)
	}
}

// DHTMode controls the client DHT lifecycle for isolated A/B testing.
type DHTMode string

const (
	DHTCloseAfterConnect DHTMode = "close-after-connect"
	DHTNoRefresh         DHTMode = "no-refresh"
	DHTCurrent           DHTMode = "current"
)

func ParseDHTMode(value string) (DHTMode, error) {
	mode := DHTMode(strings.ToLower(value))
	switch mode {
	case DHTCloseAfterConnect, DHTNoRefresh, DHTCurrent:
		return mode, nil
	default:
		return "", fmt.Errorf("unsupported DHT mode %q (want close-after-connect, no-refresh, or current)", value)
	}
}

// TunnelMode selects which data-plane tier carries forwarded traffic. "auto"
// negotiates the best tier both sides support and falls back through the cascade
// when one does not come up; the named modes force a single tier and fail rather
// than fall back, which is what makes them useful for isolating a tier under test.
type TunnelMode string

const (
	TunnelAuto      TunnelMode = "auto"
	TunnelWireGuard TunnelMode = "wireguard"
	TunnelQUIC      TunnelMode = "quic"
	TunnelLibp2p    TunnelMode = "libp2p"
)

func ParseTunnelMode(value string) (TunnelMode, error) {
	mode := TunnelMode(strings.ToLower(value))
	switch mode {
	case TunnelAuto, TunnelWireGuard, TunnelQUIC, TunnelLibp2p:
		return mode, nil
	default:
		return "", fmt.Errorf("unsupported tunnel mode %q (want auto, wireguard, quic, or libp2p)", value)
	}
}

// Config contains the libp2p settings shared by host creation, stream policy,
// and diagnostics. Defaults are selected by the CLI.
type Config struct {
	ConnectionMode    ConnectionMode
	Transport         TransportMode
	DHTMode           DHTMode
	TunnelMode        TunnelMode
	DirectDialTimeout time.Duration
	Diagnostic        bool
	RelayAddrs        []string

	// Protocols is the generation of tunnel protocol IDs this side speaks. The
	// host serves its own (CurrentProtocols); the client resolves the host's from
	// the token version it was given, so which channel a stream opens on is
	// derived from the token rather than assumed at each call site.
	//
	// The zero value means CurrentProtocols, so a Config built before a token has
	// been decoded - which is every Config the CLI builds - is already correct for
	// the host role and for anything that does not dial.
	Protocols Protocols
}

// protocols resolves the configured protocol generation, so the stream helpers
// read one value rather than repeating the zero check at each call site.
func (c Config) protocols() Protocols {
	if c.Protocols.Data == "" || c.Protocols.Negotiate == "" {
		return CurrentProtocols()
	}
	return c.Protocols
}
