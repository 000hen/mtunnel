package udp

import (
	"context"
	"fmt"
	"net"

	"mtunnel-libp2p/internal/transport"
)

// Transport forwards a UDP service: datagrams are length-prefixed over a tunnel
// stream, one stream per client source flow (see flow.go).
type Transport struct{}

// New returns a UDP transport.
func New() Transport { return Transport{} }

// Network returns the network this transport forwards.
func (Transport) Network() transport.Network { return transport.NetworkUDP }

// Forward bridges an inbound tunnel stream and the host's local UDP connection,
// preserving datagram boundaries.
func (Transport) Forward(s transport.Stream, local net.Conn) { pipeDatagrams(s, local) }

// Listen opens the client's local UDP socket on localPort and returns a Forwarder
// that maps each client source address to its own tunnel stream from opener.
func (Transport) Listen(ctx context.Context, opener transport.Opener, localPort int) (*transport.Forwarder, error) {
	pc, err := net.ListenPacket("udp", fmt.Sprintf("localhost:%d", localPort))
	if err != nil {
		return nil, err
	}

	conn := pc.(*net.UDPConn)
	serve := func() { serveLocal(ctx, opener, conn) }
	return transport.NewForwarder(conn.LocalAddr(), serve, conn.Close), nil
}
