package transport

import "fmt"

// Network names the kind of service the tunnel forwards. It is the type behind
// the -network flag, the token's network field, and Transport.Network, so the
// same value that selected the transport is the one that dials the host's local
// service and the one that selects each data-plane tier's sub-mode.
//
// It is a named string rather than an integer because it is also a wire value -
// it travels in the connection token and is passed straight to net.Dial - and a
// string keeps the encoded form self-describing and the dial argument exact.
type Network string

const (
	// NetworkTCP forwards a stream service: each local connection rides its own
	// tunnel stream as a raw byte copy.
	NetworkTCP Network = "tcp"
	// NetworkUDP forwards a datagram service: each client source address gets its
	// own tunnel stream, with datagram boundaries preserved by length prefixes.
	NetworkUDP Network = "udp"
)

// ParseNetwork validates a network name from the command line or a decoded token.
//
// It checks the spelling only. Whether the tunnel has an implementation for a
// network is a separate question with a single answer elsewhere
// (tunnel.transportFor), the same way p2p.ParseTunnelMode validates a mode that
// the tunnel's tier registry then interprets.
func ParseNetwork(value string) (Network, error) {
	switch n := Network(value); n {
	case NetworkTCP, NetworkUDP:
		return n, nil
	default:
		return "", fmt.Errorf("unsupported network type %q (want tcp or udp)", value)
	}
}

// Datagram reports whether the network is message-oriented.
//
// It is the one bit every data-plane tier needs from the network: QUIC picks its
// DATAGRAM extension over QUIC streams, and WireGuard picks its virtual UDP conn
// over its virtual TCP listener. Both sides derive it from the same network name
// carried in the token, so they cannot disagree.
func (n Network) Datagram() bool { return n == NetworkUDP }
