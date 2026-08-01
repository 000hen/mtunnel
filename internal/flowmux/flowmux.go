// Package flowmux multiplexes many forwarded connections over one message-oriented
// channel, tagging each message with the flow it belongs to.
//
// Two tiers need this and need it identically. QUIC's DATAGRAM extension gives one
// datagram channel per connection; WireGuard's UDP sub-mode gives one virtual UDP
// conn between the two devices. Either way there is a single unreliable message pipe
// and many forwarded UDP flows to carry over it, so the flow has to be named in the
// message itself:
//
//	+----------------+------------------------------------------+
//	| flow ID (4 B)  | payload                                  |
//	+----------------+------------------------------------------+
//
// An empty payload is a FIN for that flow. That sentinel is safe because internal/udp's
// framing always writes at least its own 2-byte length prefix, so an empty payload can
// never be application data and needs no flag bit of its own.
//
// The alternative - one reliable stream per flow - is what the TCP sub-modes do, and
// is rejected here for the reason these tiers exist: a retransmitted stale game packet
// is worse than a lost one, and one slow flow must not stall the others.
//
// The package is a leaf: standard library plus internal/transport, no libp2p, no
// knowledge of what the underlying channel is made of.
package flowmux

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"mtunnel-libp2p/internal/transport"
)

const (
	// Header is the size of the flow ID prefix each message carries.
	Header = 4

	// inboundBacklog is how many peer-initiated flows may wait to be accepted.
	inboundBacklog = 64

	// flowQueue is how far one flow may run ahead of its reader before messages are
	// dropped. Dropping is correct here rather than blocking: one receive loop serves
	// every flow, so making it wait on the slowest one would stall them all, and
	// dropping under overload is what the forwarded protocol already tolerates.
	flowQueue = 64
)

// Config is what a Mux needs from the channel it runs on.
type Config struct {
	// Send delivers one framed message to the peer. It must not retain the slice.
	Send func([]byte) error

	// Recv returns the next message the peer sent. The Mux takes ownership of what it
	// returns, so a Recv that reuses a buffer must copy before returning.
	Recv func() ([]byte, error)

	// Dialing selects the even flow-ID namespace. Exactly one side must set it.
	Dialing bool

	// OnDrop, when set, reports a flow discarded before anyone could accept it. It is
	// how a silently dropped connection becomes visible rather than looking identical
	// to one that never arrived.
	OnDrop func(id uint32, reason string)
}

// A Mux carries many transport.Streams over one message channel. It satisfies
// transport.Opener, so a client can hand it straight to a forwarder.
type Mux struct {
	cfg Config

	mu     sync.Mutex
	flows  map[uint32]*flow
	next   uint32
	closed bool

	inbound chan *flow

	recvDone chan struct{}
	recvErr  error

	closeOnce sync.Once
}

var _ transport.Opener = (*Mux)(nil)

// New starts a Mux and its receive loop. Close stops it; the channel underneath is
// the caller's to close, since the tier that owns it may still need it afterwards.
func New(cfg Config) *Mux {
	// IDs are namespaced by role - the dialling side allocates even, the accepting side
	// odd - mirroring QUIC's own stream-ID convention. Only the client opens flows
	// today, so collisions cannot happen, but a scheme that works only because of who
	// happens to call it is a trap for whoever adds the second caller.
	var first uint32 = 1
	if cfg.Dialing {
		first = 0
	}

	m := &Mux{
		cfg:      cfg,
		flows:    make(map[uint32]*flow),
		next:     first,
		inbound:  make(chan *flow, inboundBacklog),
		recvDone: make(chan struct{}),
	}
	go m.receive()
	return m
}

// OpenStream starts a locally initiated flow. The peer learns of it when the first
// message arrives; there is no separate open handshake to lose.
func (m *Mux) OpenStream(context.Context) (transport.Stream, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil, fmt.Errorf("flowmux: open flow: %w", net.ErrClosed)
	}
	id := m.next
	m.next += 2
	f := newFlow(id, m)
	m.flows[id] = f
	return f.stream(), nil
}

// AcceptStream returns the next flow the peer started, blocking until one arrives,
// ctx is done, or the channel underneath fails.
func (m *Mux) AcceptStream(ctx context.Context) (transport.Stream, error) {
	select {
	case f := <-m.inbound:
		return f.stream(), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-m.recvDone:
		// Drain before reporting the end, so flows that arrived just before the channel
		// died are still handed over.
		select {
		case f := <-m.inbound:
			return f.stream(), nil
		default:
		}
		if m.recvErr != nil {
			return nil, fmt.Errorf("flowmux: accept flow: %w", m.recvErr)
		}
		return nil, net.ErrClosed
	}
}

// Done closes when the receive loop has stopped, whether because the channel failed
// or because Close ended it.
func (m *Mux) Done() <-chan struct{} { return m.recvDone }

// Close ends every live flow and refuses new ones. It does not close the channel
// underneath - the tier that built it owns it, and may hand it to the next rung.
//
// The receive loop is not waited for here: it can only be unblocked by the channel
// failing, which is the tier's job to arrange, and blocking on it would make Close
// depend on a peer that may already be gone.
func (m *Mux) Close() error {
	m.closeOnce.Do(func() { m.shutAll(net.ErrClosed) })
	return nil
}

// receive runs for the life of the channel, sorting inbound messages into flows.
func (m *Mux) receive() {
	defer close(m.recvDone)

	for {
		msg, err := m.cfg.Recv()
		if err != nil {
			m.recvErr = err
			m.shutAll(err)
			return
		}
		if len(msg) < Header {
			// Too short to name a flow. Nothing this side sends looks like this, so it
			// is either corruption or another protocol; there is nothing to do with it
			// but drop it.
			continue
		}

		id := binary.BigEndian.Uint32(msg[:Header])
		payload := msg[Header:]

		if len(payload) == 0 {
			// A FIN. If the flow is already gone this is a stray for one both sides have
			// finished with - ignoring it is what stops it from being mistaken for the
			// start of a new flow.
			if f := m.take(id); f != nil {
				f.shut(io.EOF)
			}
			continue
		}

		f, fresh := m.lookupOrCreate(id)
		if f == nil {
			return // closed underneath us
		}
		if fresh {
			select {
			case m.inbound <- f:
			default:
				// The backlog is full, which means nothing is accepting.
				m.remove(f)
				if m.cfg.OnDrop != nil {
					m.cfg.OnDrop(id, "accept backlog full")
				}
				continue
			}
		}
		f.deliver(payload)
	}
}

// lookupOrCreate returns the flow for an inbound message, creating it if the peer has
// just started it. fresh reports whether it was created, which is what tells the
// receive loop to offer it to AcceptStream.
func (m *Mux) lookupOrCreate(id uint32) (f *flow, fresh bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil, false
	}
	if f, ok := m.flows[id]; ok {
		return f, false
	}
	f = newFlow(id, m)
	m.flows[id] = f
	return f, true
}

// take removes a flow by ID and returns it, or nil if it was already gone.
func (m *Mux) take(id uint32) *flow {
	m.mu.Lock()
	defer m.mu.Unlock()

	f, ok := m.flows[id]
	if !ok {
		return nil
	}
	delete(m.flows, id)
	return f
}

// remove evicts f only if f is still the flow registered under its ID.
//
// The identity check is the same guard internal/udp's flow table documents: a flow
// that closes late can otherwise evict the live replacement that has already claimed
// its ID. IDs here are allocated monotonically so reuse is not expected, but the check
// costs one comparison and removes the class of bug entirely.
func (m *Mux) remove(f *flow) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if current, ok := m.flows[f.id]; ok && current == f {
		delete(m.flows, f.id)
	}
}

// shutAll ends every flow and refuses new ones, so readers blocked on one learn why
// rather than waiting forever.
func (m *Mux) shutAll(cause error) {
	m.mu.Lock()
	m.closed = true
	live := make([]*flow, 0, len(m.flows))
	for _, f := range m.flows {
		live = append(live, f)
	}
	m.flows = make(map[uint32]*flow)
	m.mu.Unlock()

	// Outside the lock: shut only touches the flow's own state, but a closer that
	// re-entered the table would deadlock, and this is cheap insurance against that.
	for _, f := range live {
		f.shut(cause)
	}
}

// flow is one forwarded connection multiplexed over the shared channel.
type flow struct {
	id  uint32
	mux *Mux

	packets chan []byte

	// closed is closed exactly once, by shut, with err already set.
	once   sync.Once
	closed chan struct{}
	err    error
}

func newFlow(id uint32, m *Mux) *flow {
	return &flow{
		id:      id,
		mux:     m,
		packets: make(chan []byte, flowQueue),
		closed:  make(chan struct{}),
	}
}

// stream presents the flow as a transport.Stream, with internal/udp's length-prefix
// framing riding on top through the shared datagram adapter.
func (f *flow) stream() transport.Stream {
	return transport.NewDatagramStream(f.recv, f.send, f.close)
}

// shut ends the flow with a cause, once.
func (f *flow) shut(cause error) {
	f.once.Do(func() {
		f.err = cause
		close(f.closed)
	})
}

// deliver queues an inbound payload, dropping it if the reader has fallen behind. It
// never blocks: one receive loop serves every flow, so waiting on one would stall
// them all.
func (f *flow) deliver(payload []byte) {
	select {
	case f.packets <- payload:
	default:
	}
}

func (f *flow) recv() ([]byte, error) {
	select {
	case p := <-f.packets:
		return p, nil
	case <-f.closed:
		// Drain what already arrived before reporting the end, for the same reason the
		// substrate wrapper does: both cases can be ready and select would otherwise
		// discard queued data at random.
		select {
		case p := <-f.packets:
			return p, nil
		default:
			return nil, f.err
		}
	}
}

func (f *flow) send(payload []byte) error {
	select {
	case <-f.closed:
		return net.ErrClosed
	default:
	}

	frame := make([]byte, Header+len(payload))
	binary.BigEndian.PutUint32(frame[:Header], f.id)
	copy(frame[Header:], payload)

	// A message the channel cannot carry - a QUIC datagram over the path limit, say -
	// surfaces here rather than being papered over. Splitting the payload would deliver
	// a forwarded datagram the application never sent, and dropping it silently would
	// look like packet loss the peer could not diagnose; failing the flow is the only
	// option that stays honest about what happened.
	if err := f.mux.cfg.Send(frame); err != nil {
		return fmt.Errorf("flowmux: send on flow %d: %w", f.id, err)
	}
	return nil
}

// close ends the flow locally and tells the peer, so its side is released now rather
// than when something else eventually notices.
func (f *flow) close() error {
	var first bool
	f.once.Do(func() {
		first = true
		f.err = net.ErrClosed
		close(f.closed)
	})
	if !first {
		return nil
	}

	f.mux.remove(f)

	var fin [Header]byte
	binary.BigEndian.PutUint32(fin[:], f.id)
	_ = f.mux.cfg.Send(fin[:])
	return nil
}
