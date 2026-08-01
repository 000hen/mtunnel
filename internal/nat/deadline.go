package nat

import (
	"net"
	"os"
	"sync"
	"time"
)

const (
	// substrateMTU bounds one datagram taken from the punched conn.
	//
	// It is not a policy choice: pion/ice reads its sockets into buffers of exactly
	// this size (its receiveMTU) and its packet buffer silently truncates anything
	// longer on the way in, so no larger datagram can reach a reader here regardless
	// of what the buffer offered.
	substrateMTU = 8192

	// substrateQueue is how many datagrams the reader may run ahead of its consumer.
	// Beyond that it stops reading and the datagrams pion has already buffered are
	// what absorb the burst - the same backpressure a kernel socket applies, and
	// dropping under overload is what UDP does anyway.
	substrateQueue = 8
)

// deadlineConn gives a punched conn the read-deadline behaviour net.Conn promises
// and pion/ice does not.
//
// ice.Conn implements SetDeadline, SetReadDeadline and SetWriteDeadline as stubs
// that record nothing and return nil, so a successful call is no evidence the
// deadline exists. That is not a cosmetic gap. Two of this tunnel's dependencies
// release a blocked read loop by setting a deadline in the past and then waiting for
// the loop to return - wireguard-go's device.Close and quic-go's Transport.Close both
// do - and against a stub they wait forever. The only lever left is closing the ICE
// agent, which is precisely the resource that has to survive when one punched
// substrate carries a second tier after the first one failed.
//
// So the substrate's Read gets its own goroutine, and callers take datagrams from a
// channel. A deadline then releases the caller without touching the substrate. The
// goroutine stays parked in the substrate's Read; Agent.Close is what releases it,
// which is the same event that releases the sockets underneath it.
//
// The cost is one copy and one channel handoff per datagram. That is the right trade
// for a path whose packets are ~1300 bytes: it buys correct teardown for every
// consumer instead of a documented lie each one has to work around.
type deadlineConn struct {
	net.Conn

	// packets carries datagrams from the reader; free returns their buffers. Both are
	// sized substrateQueue, so returning a buffer can never block.
	packets chan []byte
	free    chan []byte

	// stopped is closed once the reader has exited and readErr holds why. readErr is
	// written before the close, so any receive on stopped observes it.
	stopped chan struct{}
	readErr error

	mu    sync.Mutex
	read  deadline
	write deadline
}

// deadline is one direction's deadline: a channel closed when it expires, plus the
// timer that will close it. A fresh channel per SetDeadline is what makes extending
// an already-expired deadline work.
type deadline struct {
	expired chan struct{}
	timer   *time.Timer
}

// withDeadlines wraps a punched conn. The wrapper does not take ownership: closing it
// closes substrate, which for an ice.Conn closes the whole agent, so Agent.Close
// remains the one place that releases it.
func withDeadlines(substrate net.Conn) *deadlineConn {
	c := &deadlineConn{
		Conn:    substrate,
		packets: make(chan []byte, substrateQueue),
		free:    make(chan []byte, substrateQueue),
		stopped: make(chan struct{}),
	}
	for range substrateQueue {
		c.free <- make([]byte, substrateMTU)
	}
	go c.pump()
	return c
}

// pump moves datagrams off the substrate until it fails. It exits on any read error,
// including the closed-conn error Agent.Close produces, and records it for Read.
func (c *deadlineConn) pump() {
	defer close(c.stopped)

	for {
		buf := <-c.free
		n, err := c.Conn.Read(buf)
		if err != nil {
			c.readErr = err
			return
		}
		c.packets <- buf[:n]
	}
}

// Read returns the next datagram, truncating it to len(p) exactly as a UDP socket
// would. It fails with os.ErrDeadlineExceeded once the read deadline has passed, and
// with the reader's error once the substrate is gone and every datagram it did
// receive has been handed back.
func (c *deadlineConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	expired := c.read.expired
	c.mu.Unlock()

	select {
	case buf := <-c.packets:
		return c.consume(p, buf), nil
	case <-expired:
		return 0, os.ErrDeadlineExceeded
	case <-c.stopped:
		// Both cases can be ready at once, and select would pick between them at
		// random. Drain first so a substrate that ended cleanly still yields the
		// datagrams it had already accepted before reporting why it stopped.
		select {
		case buf := <-c.packets:
			return c.consume(p, buf), nil
		default:
			return 0, c.readErr
		}
	}
}

// consume copies one datagram out and returns its buffer to the reader. The send
// cannot block: free holds exactly the buffers this conn created.
func (c *deadlineConn) consume(p, buf []byte) int {
	n := copy(p, buf)
	c.free <- buf[:substrateMTU]
	return n
}

// Write sends one datagram. A write deadline already in the past fails the call, but
// a deadline cannot interrupt a write in progress - the substrate is a UDP socket, so
// a send completes or fails immediately rather than blocking long enough for one to
// matter.
func (c *deadlineConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	expired := c.write.expired
	c.mu.Unlock()

	select {
	case <-expired:
		return 0, os.ErrDeadlineExceeded
	default:
	}
	return c.Conn.Write(p)
}

func (c *deadlineConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.read.set(t)
	c.write.set(t)
	return nil
}

func (c *deadlineConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.read.set(t)
	return nil
}

func (c *deadlineConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.write.set(t)
	return nil
}

// set replaces the deadline. The caller holds the mutex.
//
// Every call installs a fresh channel rather than reusing the old one, because an
// expired deadline is expressed by a closed channel and a closed channel cannot be
// reopened - which is exactly what a caller extending a deadline it had already let
// expire needs.
func (d *deadline) set(t time.Time) {
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	if t.IsZero() {
		// No deadline: a channel nothing ever closes is what "never expires" looks
		// like to the select in Read.
		d.expired = make(chan struct{})
		return
	}

	expired := make(chan struct{})
	d.expired = expired
	if remaining := time.Until(t); remaining > 0 {
		d.timer = time.AfterFunc(remaining, func() { close(expired) })
		return
	}
	close(expired)
}
