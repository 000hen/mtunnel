// Package transport defines the network-agnostic contracts that connect the
// tunnel's orchestration to its per-network forwarders. It is the leaf of the
// dependency graph: it imports only the standard library, so the tcp and udp
// adapters can satisfy these contracts without depending on libp2p.
package transport

import (
	"context"
	"io"
	"net"
)

// Stream is the slice of a libp2p stream the forwarders rely on: a byte stream
// that can also be force-closed (reset) when forwarding fails. A libp2p
// network.Stream satisfies it structurally, so the tcp and udp packages need no
// libp2p import.
type Stream interface {
	io.ReadWriteCloser
	Reset() error
}

// Opener opens a fresh tunnel stream to the remote host. The client-side
// forwarders call it once per local connection (TCP) or source flow (UDP); the
// libp2p details - protocol ID, limited-connection allowance, dial timeout - live
// in the implementation rather than in the forwarders.
type Opener interface {
	OpenStream(ctx context.Context) (Stream, error)
}

// Transport carries the network-specific behaviour of the tunnel. One
// implementation exists per supported network type; the orchestration selects it
// once and then drives TCP and UDP through the same code.
type Transport interface {
	// Network is the network this transport forwards, used both to dial the
	// host's local service and to label the connection token.
	Network() Network

	// Forward bridges a tunnel stream and the host's local connection in both
	// directions until either side ends. TCP copies raw bytes; UDP preserves
	// datagram boundaries with length-prefix framing.
	Forward(s Stream, local net.Conn)

	// Listen opens the client's local socket on localPort and returns a Forwarder
	// that bridges its traffic to the host over streams obtained from opener.
	Listen(ctx context.Context, opener Opener, localPort int) (*Forwarder, error)
}

// Forwarder is the client's local socket plus the loop that bridges its traffic
// to the host. Close stops the loop and unblocks Serve.
type Forwarder struct {
	// Addr is the local address the forwarder accepted on, including the resolved
	// port when localPort was 0.
	Addr net.Addr

	serve   func()
	closeFn func() error
}

// NewForwarder builds a Forwarder from its local address and the serve and close
// behaviour of the underlying socket.
func NewForwarder(addr net.Addr, serve func(), closeFn func() error) *Forwarder {
	return &Forwarder{Addr: addr, serve: serve, closeFn: closeFn}
}

// Serve runs the forwarding loop until Close is called. It is meant to run in its
// own goroutine.
func (f *Forwarder) Serve() { f.serve() }

// Close stops the forwarding loop and unblocks Serve.
func (f *Forwarder) Close() error { return f.closeFn() }

// Port returns the port of the local address, or 0 if it is neither TCP nor UDP.
func (f *Forwarder) Port() int {
	switch a := f.Addr.(type) {
	case *net.TCPAddr:
		return a.Port
	case *net.UDPAddr:
		return a.Port
	default:
		return 0
	}
}
