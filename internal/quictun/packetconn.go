package quictun

import (
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

	// readMu serialises reads so Close can prove none is in flight before handing the
	// substrate back. quic-go reads from a single goroutine, so it is uncontended.
	readMu sync.Mutex

	closeOnce sync.Once
	closed    chan struct{}
}

var _ net.PacketConn = (*packetConn)(nil)

func newPacketConn(substrate net.Conn) *packetConn {
	return &packetConn{
		substrate: substrate,
		local:     pinAddr(substrate.LocalAddr(), 1),
		remote:    pinAddr(substrate.RemoteAddr(), 2),
		closed:    make(chan struct{}),
	}
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
	p.readMu.Lock()
	defer p.readMu.Unlock()

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
// It must not be called from the goroutine doing the reading, which would deadlock on
// readMu. quic-go never does: with a caller-supplied Conn it leaves closing to us.
func (p *packetConn) Close() error {
	p.closeOnce.Do(func() {
		close(p.closed)
		_ = p.substrate.SetReadDeadline(time.Now())

		p.readMu.Lock()
		defer p.readMu.Unlock()
		_ = p.substrate.SetReadDeadline(time.Time{})
	})
	return nil
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
