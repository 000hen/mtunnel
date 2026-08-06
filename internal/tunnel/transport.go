package tunnel

import (
	"fmt"

	"mtunnel-libp2p/internal/tcp"
	"mtunnel-libp2p/internal/transport"
	"mtunnel-libp2p/internal/udp"
)

// transportFor returns the transport for a network. It is the single source of
// truth for which networks the tunnel supports: transport.ParseNetwork validates
// that a name is spelled like a network, and this decides whether one is actually
// implemented. Add a network by adding a case here plus a package implementing
// transport.Transport.
func transportFor(network transport.Network, diagnostic bool) (transport.Transport, error) {
	switch network {
	case transport.NetworkTCP:
		return tcp.New(diagnostic), nil
	case transport.NetworkUDP:
		return udp.New(), nil
	default:
		return nil, fmt.Errorf("unsupported network type %q", network)
	}
}

// NetworkSupported reports whether network names a transport the tunnel can use,
// returning a descriptive error if not. It lets the entry point validate the flag
// before doing any setup work.
func NetworkSupported(network transport.Network) error {
	_, err := transportFor(network, false)
	return err
}
