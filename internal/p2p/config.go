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

// Config contains the libp2p settings shared by host creation, stream policy,
// and diagnostics. Defaults are selected by the CLI.
type Config struct {
	ConnectionMode    ConnectionMode
	Transport         TransportMode
	DHTMode           DHTMode
	DirectDialTimeout time.Duration
	Diagnostic        bool
	RelayAddrs        []string
}
