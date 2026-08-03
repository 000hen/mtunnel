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

	// done releases the reader from the two channel operations no socket close can
	// reach - waiting for a free buffer, and handing a datagram to a consumer that
	// has stopped taking them. Closing the substrate only unblocks a reader parked in
	// Read, so without this a pump that filled its queue during teardown would
	// outlive the agent. stop is the one writer.
	done     chan struct{}
	stopOnce sync.Once

	mu    sync.Mutex
	read  deadline
	write deadline
}

// deadline is one direction's deadline: a channel closed when it expires, plus the
// timer that will close it.
//
// The channel is long-lived on purpose. A Read parked in its select holds whatever
// channel was current when it started, so expiring a *replacement* channel would be
// invisible to it - and releasing an already-blocked read is the entire reason this
// type exists. Only one case forces a new channel: extending a deadline that has
// already fired, since a closed channel cannot be reopened. fired records that, and
// gen lets a timer callback that lost a race against a later set recognise itself as
// stale.
type deadline struct {
	expired chan struct{}
	timer   *time.Timer
	fired   bool
	gen     uint64
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
		done:    make(chan struct{}),
		// Both channels exist from the start. A Read that runs before any deadline is
		// set still has to park on the same channel a later SetReadDeadline will close,
		// or that read would never learn the deadline arrived - see deadline.
		read:  deadline{expired: make(chan struct{})},
		write: deadline{expired: make(chan struct{})},
	}
	for range substrateQueue {
		c.free <- make([]byte, substrateMTU)
	}
	go c.pump()
	return c
}

// pump moves datagrams off the substrate until it fails or is stopped. It exits on
// any read error, including the closed-conn error Agent.Close produces, and records
// it for Read.
//
// Both channel operations are guarded by done. Neither can be released by closing
// the substrate - a pump waiting for a free buffer, or offering a datagram to a
// consumer that has stopped reading, is waiting on this conn's own channels - and
// teardown produces exactly that state: the consumer stops first, the peer keeps
// sending, and substrateQueue datagrams later the pump is parked.
func (c *deadlineConn) pump() {
	defer close(c.stopped)

	for {
		var buf []byte
		select {
		case buf = <-c.free:
		case <-c.done:
			c.readErr = net.ErrClosed
			return
		}

		n, err := c.Conn.Read(buf)
		if err != nil {
			c.readErr = err
			return
		}

		select {
		case c.packets <- buf[:n]:
		case <-c.done:
			c.readErr = net.ErrClosed
			return
		}
	}
}

// stop releases the pump. It is idempotent, and it does not touch the substrate:
// ownership of that stays with the ICE agent, which closes it separately.
func (c *deadlineConn) stop() {
	c.stopOnce.Do(func() { close(c.done) })
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

	c.set(&c.read, t)
	c.set(&c.write, t)
	return nil
}

func (c *deadlineConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.set(&c.read, t)
	return nil
}

func (c *deadlineConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.set(&c.write, t)
	return nil
}

// set replaces one direction's deadline. The caller holds the mutex.
//
// The existing channel is kept unless it has already been closed. That is what makes
// a deadline set in the past release a Read that is *already* blocked: the read is
// parked on the channel that was current when it started, so a replacement channel
// would expire unobserved and the read would hang forever. Every consumer of a
// punched substrate depends on that release - it is how a cascade rung hands the
// substrate to the next rung without closing a conn it does not own.
//
// A channel that already fired cannot be reopened, so extending an expired deadline
// is the one case that allocates.
func (c *deadlineConn) set(d *deadline, t time.Time) {
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	// Bump the generation unconditionally, so a timer callback already past its
	// Stop - running, or blocked on this very mutex - recognises itself as stale
	// instead of expiring the deadline this call is installing.
	d.gen++
	if d.expired == nil || d.fired {
		d.expired = make(chan struct{})
		d.fired = false
	}
	if t.IsZero() {
		// No deadline: a channel nothing ever closes is what "never expires" looks
		// like to the select in Read.
		return
	}
	gen := d.gen
	if remaining := time.Until(t); remaining > 0 {
		d.timer = time.AfterFunc(remaining, func() { c.expire(d, gen) })
		return
	}
	d.fired = true
	close(d.expired)
}

// expire fires a deadline from its timer, unless a later set has superseded it.
// Stop cannot make that guarantee on its own: a callback already running, or already
// blocked on the mutex, outlives the Stop that was meant to cancel it.
func (c *deadlineConn) expire(d *deadline, gen uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if d.gen != gen || d.fired {
		return
	}
	d.fired = true
	close(d.expired)
}
