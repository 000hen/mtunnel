package transport

import "net"

// ConnStream adapts a net.Conn to Stream. Every tier below the libp2p floor hands
// back plain net.Conns - a netstack TCP conn today - and Stream needs exactly one
// method they lack.
//
// Reset maps onto Close. libp2p distinguishes a reset (abort; tell the peer this
// failed) from a close (orderly end-of-stream), but a net.Conn has no abort
// primitive to map onto, and every Reset call in this codebase means "stop moving
// bytes now", which Close delivers.
type ConnStream struct {
	net.Conn
}

// CloseWrite half-closes the underlying connection when it supports it.
// Plain net.Conn has no half-close operation, so closing is the best available
// equivalent for transports without a write side to close independently.
func (c ConnStream) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return c.Conn.Close()
}

var _ Stream = ConnStream{}

// Reset closes the connection; see the type comment for why the distinction
// collapses here.
func (c ConnStream) Reset() error { return c.Conn.Close() }
