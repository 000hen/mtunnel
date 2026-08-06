package wireguard

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// ErrSubstrateAbandoned reports that Close could not release its receive loop and closed
// the substrate to break it out - a substrate this package explicitly does not own.
//
// It is worth a sentinel rather than a log line because it changes what the caller can do
// next, not merely what it knows. The tier cascade runs every rung on one punched conn,
// so a rung that closed it has not just failed: it has taken every rung below it with it,
// and a caller that keeps walking would report the next tier as broken when the substrate
// is what is gone.
var ErrSubstrateAbandoned = errors.New("wireguard: substrate abandoned")

// endpoint is the sole conn.Endpoint a Bind ever produces. A punched substrate has
// exactly one peer by construction - it is a connected socket, not a listening one -
// so there is nothing to distinguish between endpoints and no source address worth
// tracking.
//
// It is a value type with no mutable state on purpose: the device shares one
// endpoint across every received packet, so a pointer with a mutable source address
// would be a data race between the receive path and the device's own bookkeeping.
type endpoint struct {
	dst netip.AddrPort
}

func (e endpoint) ClearSrc()           {}
func (e endpoint) SrcToString() string { return "" }
func (e endpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (e endpoint) DstToString() string { return e.dst.String() }
func (e endpoint) DstIP() netip.Addr   { return e.dst.Addr() }

// DstToBytes feeds WireGuard's mac2 cookie calculation. Only self-consistency
// matters there: each side derives the cookie from its own view of the peer's
// address, and this bind reports the same address for every packet it ever sees.
func (e endpoint) DstToBytes() []byte {
	b, err := e.dst.MarshalBinary()
	if err != nil {
		return nil
	}
	return b
}

// Bind adapts a single connected substrate - the punched net.Conn from internal/nat
// - to wireguard-go's batched conn.Bind interface.
//
// conn.Bind is written for a listening UDP socket serving many peers, so most of its
// surface degenerates here: BatchSize is 1 because a net.Conn moves one datagram per
// call, ParseEndpoint ignores its argument because there is only one possible
// destination, Send ignores the endpoint it is handed for the same reason, and
// SetMark is meaningless for a socket this bind does not own.
//
// Bind prefers not to own the substrate. internal/nat's Agent owns it - the conn is
// a view onto the agent's ICE sockets, not an independent resource - so closing it
// from here makes ownership ambiguous and invites a double close. But releasing the
// receive loop is not optional: device.Close waits for the receive goroutines to
// return after calling Bind.Close, so a Read still blocked there hangs shutdown
// forever. Close therefore tries the read deadline first, restores it once the loop
// is out, and closes the substrate only when the deadline demonstrably failed to
// release the loop. See Close.
type Bind struct {
	conn net.Conn
	ep   endpoint

	mu sync.Mutex
	// closed is nil while the bind is not open. Open installs a fresh channel and
	// hands the receive closure that exact channel rather than reading the field,
	// so a re-Open cannot race a receive still unwinding from the previous one.
	closed chan struct{}
	// exited is closed by the receive closure once it has reported the close back to
	// the device, which is the only evidence Close gets that the loop has actually
	// left the substrate's Read. It is installed and captured exactly like closed.
	exited chan struct{}
	// abandoned records that Close took the fallback and closed the substrate. It is
	// kept rather than only returned because device.Close discards whatever Bind.Close
	// reports - it has no channel for it - so Tunnel.Close reads it from here instead.
	abandoned bool
}

// closeGrace bounds how long Close waits for that evidence before falling back to
// closing the substrate.
//
// A receive released by an expired read deadline returns within microseconds, so even
// a fraction of this is orders of magnitude of slack. The number is nevertheless a
// full second, because the two sides of the trade are not the same size: waiting it
// out costs a slower shutdown on a path that is already failing, while giving up too
// early costs the shared substrate and therefore every rung that had not been tried
// yet. Skipping the fallback entirely is not an option either - device.Close waits on
// the receive goroutines, so a loop that is never released hangs the process.
const closeGrace = time.Second

var (
	_ conn.Bind     = (*Bind)(nil)
	_ conn.Endpoint = endpoint{}
)

// NewBind wraps a connected substrate. The returned Bind does not close substrate;
// see the type comment.
func NewBind(substrate net.Conn) *Bind {
	return &Bind{conn: substrate, ep: endpoint{dst: remoteAddrPort(substrate)}}
}

// Endpoint returns the single endpoint this bind routes to. Callers use it to render
// the UAPI endpoint= line, which ParseEndpoint then resolves straight back to it.
func (b *Bind) Endpoint() conn.Endpoint { return b.ep }

// Open puts the bind into a receiving state.
//
// Note that device.Up calls Close before the first Open (BindUpdate closes any
// previous bind unconditionally), so Close on a bind that was never opened has to be
// a no-op rather than a permanent shutdown.
func (b *Bind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	closed := make(chan struct{})
	exited := make(chan struct{})
	b.closed = closed
	b.exited = exited

	// The device retries a receive that failed for any other reason, so only the
	// close report proves the loop is done with the substrate - and it can arrive
	// more than once if the device calls in again after being told.
	var once sync.Once
	recv := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, err := b.receive(closed, packets, sizes, eps)
		if errors.Is(err, net.ErrClosed) {
			once.Do(func() { close(exited) })
		}
		return n, err
	}
	// The substrate is already connected, so there is no port to report; echoing the
	// requested one keeps the device's own bookkeeping consistent.
	return []conn.ReceiveFunc{recv}, port, nil
}

// receive delivers one datagram from the substrate. The conn.Bind contract requires
// it to return net.ErrClosed once Close has been called, which is also what tells
// the device's receive goroutine to exit.
func (b *Bind) receive(closed chan struct{}, packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	if len(packets) == 0 || len(sizes) == 0 || len(eps) == 0 {
		return 0, errors.New("wireguard: receive called with no buffers")
	}
	for {
		select {
		case <-closed:
			return 0, net.ErrClosed
		default:
		}

		n, err := b.conn.Read(packets[0])
		if err != nil {
			select {
			case <-closed:
				// Close set a read deadline in the past to break us out of the Read
				// above; report the close rather than the timeout it manufactured.
				return 0, net.ErrClosed
			default:
			}
			var timeout net.Error
			if errors.As(err, &timeout) && timeout.Timeout() {
				// A deadline nothing in this package set. The substrate is still
				// healthy, so keep receiving rather than tear the device down.
				continue
			}
			return 0, fmt.Errorf("wireguard: read from substrate: %w", err)
		}

		sizes[0] = n
		eps[0] = b.ep
		return 1, nil
	}
}

// Close stops the receive loop, and closes the substrate only if it has to.
//
// A read deadline in the past is how a blocked receive gets released without
// touching a conn this bind would rather not own. Whether that worked cannot be
// inferred from the error: pion/ice's Conn implements SetReadDeadline as a stub that
// records nothing and returns nil, so a successful call is no evidence at all - and
// that is precisely the substrate this bind runs on in production. Wait for the
// receive to report back instead, and if it does not, close the substrate. That is
// the only lever left, and a substrate closed a moment before its owner would have
// closed it anyway beats a device.Close that never returns. It is reported as
// ErrSubstrateAbandoned rather than silently, because the owner may have had further
// use for it.
//
// When the receive does report back, the deadline is cleared before returning. The
// substrate is handed on to the next rung of the tier cascade, and a deadline left in
// the past would fail every read that rung ever attempts.
//
// One consequence worth naming: after the fallback fires this bind cannot be
// reopened, because its substrate is gone. Nothing does - a device is brought up
// once over a punched conn and torn down with it - and a Down/Up cycle would have
// nothing to reconnect to either way.
func (b *Bind) Close() error {
	b.mu.Lock()
	if b.closed == nil {
		b.mu.Unlock()
		return nil
	}
	close(b.closed)
	b.closed = nil
	exited := b.exited
	b.exited = nil
	b.mu.Unlock()

	if err := b.conn.SetReadDeadline(time.Now()); err != nil {
		return b.abandon("substrate refused a read deadline", err)
	}

	// Deliberately not under the mutex: this waits, and holding it would block a
	// concurrent Open behind a shutdown for as long as the grace lasts.
	timer := time.NewTimer(closeGrace)
	defer timer.Stop()
	select {
	case <-exited:
		// The receive loop is out of the substrate's Read, so the deadline that
		// released it has done its job. Clearing it is not tidiness: the substrate
		// outlives this bind and carries the next rung of the cascade, which would
		// otherwise inherit a deadline permanently in the past and fail every read it
		// ever makes. quictun's packetConn.Close restores it for the same reason.
		_ = b.conn.SetReadDeadline(time.Time{})
		return nil
	case <-timer.C:
		// Deliberately no SetReadDeadline(time.Time{}) here: the expired deadline is the
		// only thing still trying to release the parked receive.
		return b.abandon("receive loop did not exit within the close grace", nil)
	}
}

// abandon closes the substrate as the last way to release a receive that would not let
// go, and reports it as the consequential event it is.
//
// The warning is unconditional. Every other line this package emits is diagnostic detail
// about a tunnel that is working; this one says a resource shared with code outside the
// package is gone, and it is the difference between "the QUIC tier failed too" and "there
// was nothing left for the QUIC tier to run on".
func (b *Bind) abandon(reason string, cause error) error {
	b.mu.Lock()
	b.abandoned = true
	b.mu.Unlock()

	attrs := []any{"tier", "wireguard", "reason", reason, "grace_ms", closeGrace.Milliseconds()}
	if cause != nil {
		attrs = append(attrs, "error", cause.Error())
	}
	slog.Warn("tunnel_substrate_abandoned", attrs...)

	// The close error itself is not worth reporting: the substrate is unusable either
	// way, and the sentinel is what the caller acts on.
	_ = b.conn.Close()
	return fmt.Errorf("%w: %s", ErrSubstrateAbandoned, reason)
}

// Abandoned reports whether Close closed the substrate. Tunnel.Close asks, because
// device.Close swallows the error Close returns.
func (b *Bind) Abandoned() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.abandoned
}

// Send writes each packet to the substrate. ep is ignored: the substrate is
// connected to the only peer this bind can reach.
func (b *Bind) Send(bufs [][]byte, _ conn.Endpoint) error {
	for _, buf := range bufs {
		if _, err := b.conn.Write(buf); err != nil {
			return fmt.Errorf("wireguard: write to substrate: %w", err)
		}
	}
	return nil
}

// ParseEndpoint ignores s and returns the single reachable endpoint. The UAPI
// endpoint= line has to name something, but with a connected substrate the name
// cannot change where packets go.
func (b *Bind) ParseEndpoint(string) (conn.Endpoint, error) { return b.ep, nil }

// SetMark is a no-op: SO_MARK belongs to a socket this bind does not own.
func (b *Bind) SetMark(uint32) error { return nil }

// BatchSize is 1 because a net.Conn carries one datagram per Read/Write.
func (b *Bind) BatchSize() int { return 1 }

// remoteAddrPort reports the substrate's peer address, for endpoint bookkeeping
// only: every send goes to the connected substrate whatever this returns. An address
// that cannot be resolved therefore degrades to the zero value instead of failing
// the tunnel.
func remoteAddrPort(c net.Conn) netip.AddrPort {
	addr := c.RemoteAddr()
	if addr == nil {
		return netip.AddrPort{}
	}
	if ap, err := netip.ParseAddrPort(addr.String()); err == nil {
		return ap
	}
	return netip.AddrPort{}
}
