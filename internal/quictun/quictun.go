// Package quictun carries tunnel traffic over a QUIC connection running directly on
// a hole-punched UDP substrate, with no libp2p involvement in the data path.
//
// It is the cascade's second rung, below WireGuard and above the libp2p floor, and it
// offers two sub-modes chosen by what is being forwarded:
//
//   - Forwarded TCP gets one QUIC stream per connection, mirroring how the libp2p
//     tier multiplexes one stream per connection over one libp2p connection today.
//   - Forwarded UDP gets QUIC's DATAGRAM extension, so a lost packet is not
//     retransmitted and one slow flow cannot stall another. That is the whole point
//     of reaching for this tier over a reliable stream: a reliable ordered channel
//     under UDP traffic reintroduces exactly the head-of-line blocking that carrying
//     game traffic over a libp2p stream already suffers from.
//
// The package never imports libp2p. It receives a punched net.Conn and a peer
// certificate fingerprint, both arranged elsewhere, and owns nothing but the QUIC
// connection built on top.
package quictun

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"mtunnel-libp2p/internal/flowmux"
	"mtunnel-libp2p/internal/transport"
)

const (
	// defaultHandshakeTimeout bounds the TLS 1.3 exchange. A punched path is already
	// working by the time this runs, so a handshake that has not completed in a few
	// seconds is not going to.
	defaultHandshakeTimeout = 6 * time.Second

	// defaultKeepAlive and defaultMaxIdle keep the connection alive across a NAT
	// binding's idle timeout. The keepalive is well under the idle limit so a single
	// lost PING does not tear the tunnel down.
	defaultKeepAlive = 15 * time.Second
	defaultMaxIdle   = 60 * time.Second

	// maxIncomingStreams is generous because one forwarded TCP connection costs one
	// stream, and a browser or a game client opens many at once.
	maxIncomingStreams = 1024

	// closeCode is the application error code used for orderly teardown. Nothing
	// interprets it; the tunnel has no application error taxonomy.
	closeCode = 0

	// muxDrainTimeout bounds how long Close waits for the datagram receive loop to
	// notice the connection has ended. It is generous because the loop normally exits
	// immediately, and it exists only so a wedged connection cannot hang shutdown.
	muxDrainTimeout = 2 * time.Second
)

// Config is everything the tier needs beyond the substrate itself.
type Config struct {
	// Identity is this side's ephemeral certificate. Required.
	Identity *Identity

	// PeerFingerprint pins the peer's certificate, and arrives over the authenticated
	// negotiate stream. Required: without it there is nothing to authenticate against.
	PeerFingerprint [32]byte

	// Datagrams selects the DATAGRAM sub-mode instead of streams. It must match on
	// both sides, which it does because both derive it from the same -network value
	// carried in the token.
	Datagrams bool

	// HandshakeTimeout, KeepAlive and MaxIdle are optional; zero means the default.
	HandshakeTimeout time.Duration
	KeepAlive        time.Duration
	MaxIdle          time.Duration

	Diagnostic bool
}

func (c Config) handshakeTimeout() time.Duration {
	if c.HandshakeTimeout > 0 {
		return c.HandshakeTimeout
	}
	return defaultHandshakeTimeout
}

func (c Config) quic() *quic.Config {
	keepAlive, maxIdle := c.KeepAlive, c.MaxIdle
	if keepAlive <= 0 {
		keepAlive = defaultKeepAlive
	}
	if maxIdle <= 0 {
		maxIdle = defaultMaxIdle
	}
	return &quic.Config{
		EnableDatagrams:      c.Datagrams,
		HandshakeIdleTimeout: c.handshakeTimeout(),
		KeepAlivePeriod:      keepAlive,
		MaxIdleTimeout:       maxIdle,
		MaxIncomingStreams:   maxIncomingStreams,

		// The substrate is not a kernel UDP socket: there is no DF bit to probe with
		// and pion hands over whole datagrams, so path MTU discovery has nothing to
		// measure and could only blackhole packets by guessing high. Staying at the
		// conservative initial packet size costs throughput nothing measurable and is
		// what keeps the datagram sub-mode's size limit predictable.
		DisablePathMTUDiscovery: true,
	}
}

// Tunnel is an established QUIC connection over the punched substrate. It satisfies
// transport.Opener, so the client side can hand it straight to a forwarder.
type Tunnel struct {
	pc   *packetConn
	tr   *quic.Transport
	ln   *quic.Listener // accepting side only
	conn *quic.Conn

	datagrams  bool
	diagnostic bool

	// mux is set in the datagram sub-mode only, and carries every forwarded flow over
	// the connection's single datagram channel.
	mux *flowmux.Mux

	closeOnce sync.Once
	closeErr  error
}

var _ transport.Opener = (*Tunnel)(nil)

// Dial completes a QUIC handshake as the initiating side. substrate must honour read
// deadlines; see packetConn for why that is load-bearing rather than pedantic.
func Dial(ctx context.Context, substrate net.Conn, cfg Config) (*Tunnel, error) {
	return start(ctx, substrate, cfg, true)
}

// Accept completes a QUIC handshake as the responding side.
func Accept(ctx context.Context, substrate net.Conn, cfg Config) (*Tunnel, error) {
	return start(ctx, substrate, cfg, false)
}

func start(ctx context.Context, substrate net.Conn, cfg Config, dialing bool) (*Tunnel, error) {
	if cfg.Identity == nil {
		return nil, errors.New("quictun: no local identity")
	}
	if !validFingerprint(cfg.PeerFingerprint) {
		return nil, errors.New("quictun: peer supplied no certificate fingerprint")
	}

	role := "accept"
	if dialing {
		role = "dial"
	}

	pc := newPacketConn(substrate)
	tr := &quic.Transport{Conn: pc}

	handshakeCtx, cancel := context.WithTimeout(ctx, cfg.handshakeTimeout())
	defer cancel()

	var (
		ln   *quic.Listener
		conn *quic.Conn
		err  error
	)
	if dialing {
		conn, err = tr.Dial(handshakeCtx, pc.remote, cfg.Identity.clientTLS(cfg.PeerFingerprint), cfg.quic())
	} else {
		if ln, err = tr.Listen(cfg.Identity.serverTLS(cfg.PeerFingerprint), cfg.quic()); err == nil {
			conn, err = ln.Accept(handshakeCtx)
		}
	}
	if err != nil {
		// Joined, not discarded: a handshake that failed is one thing, and a teardown
		// that had to close the shared substrate to unwind is another, and the caller
		// walking the cascade acts on the second.
		return nil, errors.Join(fmt.Errorf("quictun: %s: %w", role, err), release(ln, tr, pc))
	}

	// Datagram support is negotiated inside the handshake, so this is the first
	// moment it can be checked. Failing here drops to the next rung, which is the
	// right answer: silently falling back to streams would hand UDP traffic a
	// reliable ordered channel, the exact behaviour this tier exists to avoid.
	if cfg.Datagrams {
		if state := conn.ConnectionState(); !state.SupportsDatagrams.Local || !state.SupportsDatagrams.Remote {
			_ = conn.CloseWithError(closeCode, "datagrams unsupported")
			release(ln, tr, pc)
			return nil, errors.New("quictun: peer did not enable QUIC datagram support")
		}
	}

	t := &Tunnel{
		pc:         pc,
		tr:         tr,
		ln:         ln,
		conn:       conn,
		datagrams:  cfg.Datagrams,
		diagnostic: cfg.Diagnostic,
	}
	if cfg.Datagrams {
		t.mux = t.newMux(dialing)
	}

	if cfg.Diagnostic {
		mode := "stream"
		if cfg.Datagrams {
			mode = "datagram"
		}
		slog.Info("tunnel_quic_ready",
			"role", role,
			"mode", mode,
			"remote", conn.RemoteAddr().String(),
			"version", conn.ConnectionState().Version.String(),
		)
	}
	return t, nil
}

// release tears down a partially built tier in the reverse of construction order.
// The transport goes before the packet conn because closing it needs a working read
// deadline on the substrate, which the packet conn is what provides.
//
// It returns only the packet conn's error, and only because that is where
// ErrSubstrateAbandoned comes from. The listener's and transport's own close errors say
// nothing a caller who is already unwinding could use.
func release(ln *quic.Listener, tr *quic.Transport, pc *packetConn) error {
	if ln != nil {
		_ = ln.Close()
	}
	_ = tr.Close()
	return pc.Close()
}

// OpenStream starts a new forwarded connection: a QUIC stream, or a datagram flow in
// the datagram sub-mode.
func (t *Tunnel) OpenStream(ctx context.Context) (transport.Stream, error) {
	if t.mux != nil {
		return t.mux.OpenStream(ctx)
	}
	s, err := t.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("quictun: open stream: %w", err)
	}
	return quicStream{s}, nil
}

// AcceptStream returns the next forwarded connection the peer started. It blocks
// until one arrives, ctx is done, or the connection ends.
func (t *Tunnel) AcceptStream(ctx context.Context) (transport.Stream, error) {
	if t.mux != nil {
		return t.mux.AcceptStream(ctx)
	}
	s, err := t.conn.AcceptStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("quictun: accept stream: %w", err)
	}
	return quicStream{s}, nil
}

// Done closes when the QUIC connection ends, whether the peer went away or this side
// closed it. The host side watches it to notice a departed peer.
func (t *Tunnel) Done() <-chan struct{} { return t.conn.Context().Done() }

// Close tears the tier down and normally hands the substrate back untouched, so a later
// rung or the ICE agent's own shutdown can still use it. When it could not, it returns
// ErrSubstrateAbandoned. It is safe to call more than once.
func (t *Tunnel) Close() error {
	t.closeOnce.Do(func() {
		_ = t.conn.CloseWithError(closeCode, "tunnel closed")
		if t.mux != nil {
			_ = t.mux.Close()
			// The mux's receive loop wakes on the connection's context, which
			// CloseWithError has just cancelled. Bound the wait anyway: shutdown must
			// not depend on quic-go doing that promptly.
			ctx, cancel := context.WithTimeout(context.Background(), muxDrainTimeout)
			t.waitMuxDone(ctx)
			cancel()
		}
		if t.ln != nil {
			_ = t.ln.Close()
		}
		// The packet conn's error is kept because ErrSubstrateAbandoned comes out of it,
		// and joined rather than preferred because a transport that failed to close is
		// still worth reporting on a path where nothing else will.
		t.closeErr = errors.Join(t.tr.Close(), t.pc.Close())
	})
	return t.closeErr
}

// quicStream adapts a QUIC stream to transport.Stream.
//
// CloseWrite is not part of that interface but the TCP forwarder probes for it, and
// mapping it onto the stream's own half-close is what lets a forwarded connection
// signal end-of-data without discarding what is still arriving the other way.
type quicStream struct {
	*quic.Stream
}

var _ transport.Stream = quicStream{}

// CloseWrite ends this side's half of the stream, leaving the peer's half open.
func (s quicStream) CloseWrite() error { return s.Stream.Close() }

// Close ends both halves: the write side with a FIN, the read side by telling the
// peer to stop sending. libp2p's Close does the same, and the forwarders rely on it -
// a Close that left the read side open would leave the reading goroutine parked.
func (s quicStream) Close() error {
	s.Stream.CancelRead(closeCode)
	return s.Stream.Close()
}

// Reset aborts both directions without waiting for anything in flight.
func (s quicStream) Reset() error {
	s.Stream.CancelWrite(closeCode)
	s.Stream.CancelRead(closeCode)
	return nil
}
