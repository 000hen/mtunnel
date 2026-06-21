package main

import (
	"context"
	"fmt"
	"net"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// transport carries the network-specific behaviour of the tunnel. One
// implementation exists per supported network type; runHost and runClient select
// it once with transportFor and then drive TCP and UDP through the same code.
type transport interface {
	// network is the canonical network name ("tcp" or "udp"), used both to dial
	// the host's local service and to label the connection token.
	network() string

	// forward bridges a tunnel stream and the host's local connection in both
	// directions until either side ends. TCP copies raw bytes; UDP preserves
	// datagram boundaries with length-prefix framing.
	forward(s network.Stream, local net.Conn)

	// listenLocal opens the client's local socket on localPort and returns a
	// forwarder that bridges its traffic to target over tunnel streams.
	listenLocal(ctx context.Context, h host.Host, target peer.ID, localPort int) (*localForwarder, error)
}

// transportFor returns the transport for a network type. It is the single source
// of truth for which networks the tunnel supports.
func transportFor(networkType string) (transport, error) {
	switch networkType {
	case "tcp":
		return tcpTransport{}, nil
	case "udp":
		return udpTransport{}, nil
	default:
		return nil, fmt.Errorf("unsupported network type %q", networkType)
	}
}

// localForwarder is the client's local socket plus the loop that bridges its
// traffic to the host. close stops the loop and unblocks serve.
type localForwarder struct {
	addr  net.Addr
	close func() error
	serve func()
}

// addrPort extracts the port from a TCP or UDP local address.
func addrPort(addr net.Addr) int {
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.Port
	case *net.UDPAddr:
		return a.Port
	default:
		return 0
	}
}

// tcpTransport forwards a TCP service: each local connection rides a tunnel
// stream as a raw byte copy.
type tcpTransport struct{}

func (tcpTransport) network() string { return "tcp" }

func (tcpTransport) forward(s network.Stream, local net.Conn) { pipe(s, local) }

func (t tcpTransport) listenLocal(ctx context.Context, h host.Host, target peer.ID, localPort int) (*localForwarder, error) {
	listen, err := net.Listen(t.network(), fmt.Sprintf("localhost:%d", localPort))
	if err != nil {
		return nil, err
	}

	return &localForwarder{
		addr:  listen.Addr(),
		close: listen.Close,
		serve: func() { acceptLocalConns(ctx, h, target, listen) },
	}, nil
}

// udpTransport forwards a UDP service: datagrams are length-prefixed over a
// tunnel stream, one stream per client source flow (see udp.go).
type udpTransport struct{}

func (udpTransport) network() string { return "udp" }

func (udpTransport) forward(s network.Stream, local net.Conn) { pipeDatagrams(s, local) }

func (t udpTransport) listenLocal(ctx context.Context, h host.Host, target peer.ID, localPort int) (*localForwarder, error) {
	pc, err := net.ListenPacket(t.network(), fmt.Sprintf("localhost:%d", localPort))
	if err != nil {
		return nil, err
	}

	conn := pc.(*net.UDPConn)
	return &localForwarder{
		addr:  conn.LocalAddr(),
		close: conn.Close,
		serve: func() { serveLocalUDP(ctx, h, target, conn) },
	}, nil
}
