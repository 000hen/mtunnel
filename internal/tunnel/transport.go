package tunnel

import (
	"fmt"

	"mtunnel-libp2p/internal/tcp"
	"mtunnel-libp2p/internal/transport"
	"mtunnel-libp2p/internal/udp"
)

// transportFor returns the transport for a network type. It is the single source
// of truth for which networks the tunnel supports.
func transportFor(network string) (transport.Transport, error) {
	switch network {
	case "tcp":
		return tcp.New(), nil
	case "udp":
		return udp.New(), nil
	default:
		return nil, fmt.Errorf("unsupported network type %q", network)
	}
}

// NetworkSupported reports whether network names a transport the tunnel can use,
// returning a descriptive error if not. It lets the entry point validate the flag
// before doing any setup work.
func NetworkSupported(network string) error {
	_, err := transportFor(network)
	return err
}
