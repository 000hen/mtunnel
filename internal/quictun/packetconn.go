package quictun

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// packetConn presents the punched conn to quic-go as the net.PacketConn it expects.
//
// The substrate is already point-to-point: ICE nominated exactly one candidate pair,
// so there is only ever one peer to read from or write to. That makes the address
// arguments in the net.PacketConn contract vestigial here - every read reports the
// same remote, every write ignores the address it is handed.
//
// It deliberately does not own the substrate. A punch is expensive and is shared
// across the cascade: if the QUIC tier fails, the next rung runs on this same conn.
// So Close only detaches quic-go, leaving the substrate for whoever comes next, and
// closing it for good stays the ICE agent's job.
//
// Two quic-go behaviours shape this type, both verified against v0.59.0 rather than
// assumed:
//
//   - Transport.Close does not close a caller-supplied Conn (only one it created
//     itself). It sets a read deadline in the past to break its read loop out, waits
//     for the loop, then restores the zero deadline. So the substrate must honour
//     read deadlines - which is exactly what nat's wrapper provides - and detaching
//     afterwards is on us.
//   - Its read loop distinguishes temporary from permanent errors by a direct
//     err.(net.Error) type assertion, not errors.As. Errors from ReadFrom therefore
//     have to travel unwrapped, or a timeout would be misread as a fatal error.
type packetConn struct {
	substrate net.Conn
	local     *net.UDPAddr
	remote    *net.UDPAddr

	// reading serialises reads so Close can prove none is in flight before handing the
	// substrate back. quic-go reads from a single goroutine, so it is uncontended.
	//
	// A one-token channel rather than a mutex, because Close has to be able to give
	// up: a substrate whose read deadlines do not work would never hand the token
	// back, and sync.Mutex offers no way to stop waiting.
	reading chan struct{}

	closeOnce sync.Once
	closed    chan struct{}
	closeErr  error
}

// closeGrace bounds how long Close waits for the reader to report back before
// falling back to closing the substrate. It matches wireguard.Bind's constant, and
// for the same reason: a read released by an expired deadline returns within
// microseconds, so this is orders of magnitude of slack, while not waiting at all
// would hand the next rung a substrate with a live reader still on it - and waiting
// forever would mean a process that never exits. The generosity is deliberate, since
// the two errors cost very different amounts: waiting too long delays a teardown, and
// giving up too early destroys a substrate other rungs were going to need.
const closeGrace = time.Second

// ErrSubstrateAbandoned reports that Close could not release its reader and closed the
// substrate to break it out - a substrate this package does not own.
//
// It mirrors wireguard.ErrSubstrateAbandoned rather than sharing it. The two packages
// have no dependency on one another and neither is the substrate's owner; the only place
// that needs both answers to mean the same thing is the cascade that runs them in turn,
// which already imports both.
var ErrSubstrateAbandoned = errors.New("quictun: substrate abandoned")

var _ net.PacketConn = (*packetConn)(nil)

func newPacketConn(substrate net.Conn) *packetConn {
	p := &packetConn{
		substrate: substrate,
		local:     pinAddr(substrate.LocalAddr(), 1),
		remote:    pinAddr(substrate.RemoteAddr(), 2),
		reading:   make(chan struct{}, 1),
		closed:    make(chan struct{}),
	}
	p.reading <- struct{}{}
	return p
}

// pinAddr resolves one end of the substrate to a fixed *net.UDPAddr, captured once.
//
// Reading through to the live ICE conn on every call would be worse in two ways: it
// can return nil while the agent has no selected pair, and quic-go treats a changed
// address as connection migration and would start validating a path that never
// actually moved. The fallback exists because a substrate need not have addresses at
// all - only that they stay put and stay distinct.
func pinAddr(addr net.Addr, seq byte) *net.UDPAddr {
	if udp, ok := addr.(*net.UDPAddr); ok && udp != nil {
		return udp
	}
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, seq), Port: 1}
}

func (p *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	<-p.reading
	defer func() { p.reading <- struct{}{} }()

	select {
	case <-p.closed:
		return 0, nil, net.ErrClosed
	default:
	}

	n, err := p.substrate.Read(b)
	if err != nil {
		select {
		case <-p.closed:
			// Close put a read deadline in the past to break us out of the read
			// above; report the detach rather than the timeout it manufactured.
			return 0, nil, net.ErrClosed
		default:
		}
		return 0, nil, err
	}
	return n, p.remote, nil
}

// WriteTo ignores addr: the substrate has exactly one peer and no way to reach any
// other, so honouring an address would mean silently sending somewhere else.
func (p *packetConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	select {
	case <-p.closed:
		return 0, net.ErrClosed
	default:
	}
	return p.substrate.Write(b)
}

// Close detaches quic-go from the substrate without closing it.
//
// It breaks any in-flight read with a past deadline, then waits for that read to
// return before restoring the zero deadline - so the next tier inherits a conn with
// no stale deadline and no reader still holding a claim on the next datagram.
//
// The wait is bounded. Whether the past deadline worked cannot be inferred from its
// error - ice.Conn implements SetReadDeadline as a stub that returns nil without
// recording anything, and that is the substrate this runs on in production - so the
// only evidence is the reader reporting back. If it does not within closeGrace, the
// substrate is closed instead, and reported as ErrSubstrateAbandoned: a reader that
// cannot be released has already made it unusable for whatever comes next, and QUIC is
// the last rung above the libp2p floor, which does not use the substrate at all.
// wireguard.Bind.Close makes the same trade for the same reason - and being below
// WireGuard in the cascade rather than above it, its version of this is the one that
// costs a rung.
//
// It must not be called from the goroutine doing the reading, which would spend the
// whole grace period waiting for itself. quic-go never does: with a caller-supplied
// Conn it leaves closing to us.
func (p *packetConn) Close() error {
	p.closeOnce.Do(func() { p.closeErr = p.detach() })
	return p.closeErr
}

func (p *packetConn) detach() error {
	close(p.closed)
	_ = p.substrate.SetReadDeadline(time.Now())

	timer := time.NewTimer(closeGrace)
	defer timer.Stop()

	select {
	case <-p.reading:
		// The reader is out of the substrate's Read, so the deadline that released it
		// has done its job and must go: the substrate outlives this conn, and one
		// left permanently in the past would fail every read the next rung makes.
		_ = p.substrate.SetReadDeadline(time.Time{})
		// Hand the token back so a later ReadFrom still terminates - it sees closed
		// and returns net.ErrClosed rather than blocking on a token nobody holds.
		p.reading <- struct{}{}
		return nil
	case <-timer.C:
		// Deliberately no SetReadDeadline(time.Time{}) here: the expired deadline is
		// the only thing still trying to release the parked reader.
		//
		// The warning is unconditional, unlike every other line this package emits. The
		// rest describe a tier that is working; this one says a resource shared with the
		// rest of the cascade is gone, which is the difference between a rung that failed
		// and a rung that had nothing left to fail on.
		slog.Warn("tunnel_substrate_abandoned",
			"tier", "quic",
			"reason", "reader did not exit within the close grace",
			"grace_ms", closeGrace.Milliseconds(),
		)
		// The close error is not worth reporting: the substrate is unusable either way,
		// and the sentinel is what a caller acts on.
		_ = p.substrate.Close()
		return fmt.Errorf("%w: reader did not exit within %s", ErrSubstrateAbandoned, closeGrace)
	}
}

func (p *packetConn) LocalAddr() net.Addr { return p.local }

func (p *packetConn) SetDeadline(t time.Time) error      { return p.substrate.SetDeadline(t) }
func (p *packetConn) SetReadDeadline(t time.Time) error  { return p.substrate.SetReadDeadline(t) }
func (p *packetConn) SetWriteDeadline(t time.Time) error { return p.substrate.SetWriteDeadline(t) }

// SetReadBuffer and SetWriteBuffer exist only to keep quic-go quiet.
//
// It probes for them to size the kernel socket buffers, and prints a warning about
// UDP buffer sizes when they are missing. There is no kernel socket here - the
// substrate's buffering is pion's and the sizes are already chosen - so accepting the
// request and doing nothing is honest. Deliberately absent alongside them:
// SyscallConn, whose presence would make quic-go verify the sizes actually changed.
func (p *packetConn) SetReadBuffer(int) error  { return nil }
func (p *packetConn) SetWriteBuffer(int) error { return nil }
