// Package flowmux multiplexes many forwarded connections over one message-oriented
// channel, tagging each message with the flow it belongs to.
//
// Two tiers need this and need it identically. QUIC's DATAGRAM extension gives one
// datagram channel per connection; WireGuard's UDP sub-mode gives one virtual UDP
// conn between the two devices. Either way there is a single unreliable message pipe
// and many forwarded UDP flows to carry over it, so the flow has to be named in the
// message itself:
//
//	+----------------+------+-----------------------------------+
//	| flow ID (4 B)  | kind | payload                           |
//	+----------------+------+-----------------------------------+
//
// DATA carries a forwarded datagram. FIN and FIN_ACK are retried control frames: the
// channel is deliberately unreliable, so a one-shot close would leak the peer's flow.
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
	"time"

	"mtunnel-libp2p/internal/transport"
)

const (
	// Header is the size of the flow ID and kind prefix each message carries.
	Header = 5

	// inboundBacklog is how many peer-initiated flows may wait to be accepted.
	inboundBacklog = 64

	// flowQueue is how far one flow may run ahead of its reader before messages are
	// dropped. Dropping is correct here rather than blocking: one receive loop serves
	// every flow, so making it wait on the slowest one would stall them all, and
	// dropping under overload is what the forwarded protocol already tolerates.
	flowQueue = 64

	defaultFINRetryInterval = time.Second
	defaultFINRetryCount    = 3
	defaultIdleTimeout      = 2 * time.Minute
	defaultTombstoneTTL     = time.Minute
	defaultMaxPending       = 1024
	defaultMaxTombstones    = 1024
)

type frameKind byte

const (
	frameData frameKind = iota
	frameFIN
	frameFINAck
)

// Config is what a Mux needs from the channel it runs on.
type Config struct {
	// Send delivers one framed message to the peer. It must not retain the slice.
	//
	// That is load-bearing, not advisory: flow.send hands over a pooled buffer and
	// reuses it as soon as Send returns, so an implementation that queued the slice
	// for later would transmit whatever the next flow wrote into it. Both current
	// implementations comply - wireguard's UDPMux.send is a synchronous conn.Write,
	// and quic-go's SendDatagram copies into the frame it queues - and a new one that
	// cannot must copy before returning.
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

	// FINRetryInterval and FINRetryCount bound reliable flow teardown. Zero values use
	// conservative defaults. FINRetryCount is the number of retransmissions after the
	// initial FIN.
	FINRetryInterval time.Duration
	FINRetryCount    int

	// IdleTimeout releases a flow if every FIN was lost. Zero uses a conservative
	// default. TombstoneTTL keeps a recently closed peer flow from being resurrected by
	// late DATA; MaxPending and MaxTombstones bound control-plane memory.
	IdleTimeout   time.Duration
	TombstoneTTL  time.Duration
	MaxPending    int
	MaxTombstones int
}

// A Mux carries many transport.Streams over one message channel. It satisfies
// transport.Opener, so a client can hand it straight to a forwarder.
type Mux struct {
	cfg Config

	mu         sync.Mutex
	flows      map[uint32]*flow
	pending    map[uint32]*pendingFIN
	tombstones map[uint32]time.Time
	next       uint32
	closed     bool
	sendMu     sync.Mutex

	inbound chan *flow

	recvDone chan struct{}
	recvErr  error

	maintStop chan struct{}
	maintDone chan struct{}
	stopOnce  sync.Once
	closeOnce sync.Once
}

type pendingFIN struct {
	next    time.Time
	retries int
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
		cfg:        cfg,
		flows:      make(map[uint32]*flow),
		pending:    make(map[uint32]*pendingFIN),
		tombstones: make(map[uint32]time.Time),
		next:       first,
		inbound:    make(chan *flow, inboundBacklog),
		recvDone:   make(chan struct{}),
		maintStop:  make(chan struct{}),
		maintDone:  make(chan struct{}),
	}
	go m.receive()
	go m.maintain()
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
// depend on a peer that may already be gone. The maintenance loop is ours, so Close
// does stop and wait for it.
func (m *Mux) Close() error {
	m.closeOnce.Do(func() {
		m.stopMaintenance()
		m.shutAll(net.ErrClosed)
	})
	return nil
}

// receive runs for the life of the channel, sorting inbound messages into flows.
func (m *Mux) receive() {
	defer close(m.recvDone)

	for {
		msg, err := m.cfg.Recv()
		if err != nil {
			m.recvErr = err
			m.stopMaintenance()
			m.shutAll(err)
			return
		}
		if len(msg) < Header {
			// Too short to name a flow. Nothing this side sends looks like this, so it
			// is either corruption or another protocol; there is nothing to do with it
			// but drop it.
			continue
		}
		m.handle(msg)
	}
}

// handle sorts one complete channel message into its flow. It is kept separate from
// receive so the wire-state transitions can be tested without timer or scheduler
// races.
func (m *Mux) handle(msg []byte) {
	if len(msg) < Header {
		return
	}

	id := binary.BigEndian.Uint32(msg[:4])
	kind := frameKind(msg[4])
	payload := msg[Header:]

	switch kind {
	case frameFIN:
		if len(payload) != 0 {
			return
		}
		f := m.takeAndTombstone(id)
		if f != nil {
			f.shut(io.EOF)
		}
		_ = m.sendControl(id, frameFINAck)
		return
	case frameFINAck:
		if len(payload) == 0 {
			m.acknowledgeFIN(id)
		}
		return
	case frameData:
		if len(payload) == 0 {
			return
		}
	default:
		return
	}

	f, fresh := m.lookupOrCreate(id)
	if f == nil {
		if m.stopped() {
			return // closed underneath us
		}
		if m.tombstoned(id) {
			return // late DATA for a flow a FIN already closed
		}
		// The peer named an ID this side allocates and there is no such flow, so
		// there is nothing to deliver to - see lookupOrCreate. Report it: a message
		// that names an impossible flow is a peer bug or a stale frame, and both
		// are worth seeing rather than silently discarding.
		if m.cfg.OnDrop != nil {
			m.cfg.OnDrop(id, "flow ID in local namespace")
		}
		return
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
			return
		}
	}
	f.deliver(payload)
}

func (m *Mux) tombstoned(id uint32) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.tombstones[id]
	return ok
}

// lookupOrCreate returns the flow for an inbound message, creating it if the peer has
// just started it. fresh reports whether it was created, which is what tells the
// receive loop to offer it to AcceptStream. A nil flow means either the mux closed or
// the ID was refused; the caller tells them apart with stopped.
//
// Creation is restricted to the peer's half of the ID space, which is what makes the
// namespace split in New an invariant rather than a convention. A flow created at an
// ID this side allocates would be overwritten the moment OpenStream reached that ID,
// leaving two streams stamped identically on the wire and their traffic interleaved.
//
// Only creation is restricted. A data message or a FIN arriving on an ID this side
// opened is the peer's half of that flow and is entirely legitimate - both find the
// flow already in the table and never reach the check.
func (m *Mux) lookupOrCreate(id uint32) (f *flow, fresh bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil, false
	}
	if f, ok := m.flows[id]; ok {
		return f, false
	}
	if _, closed := m.tombstones[id]; closed {
		return nil, false
	}
	if (id&1 == 0) == m.cfg.Dialing {
		return nil, false
	}
	f = newFlow(id, m)
	m.flows[id] = f
	return f, true
}

// stopped reports whether the mux has shut down, which is how receive distinguishes
// a refused ID from a mux that closed underneath it.
func (m *Mux) stopped() bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.closed
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

// takeAndTombstone prevents a FIN that overtakes DATA from allowing the late data to
// create a new peer flow. The table is deliberately bounded because the peer controls
// the IDs it sends us.
func (m *Mux) takeAndTombstone(id uint32) *flow {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.addTombstoneLocked(id, time.Now().Add(m.tombstoneTTL()))
	f := m.flows[id]
	delete(m.flows, id)
	return f
}

func (m *Mux) acknowledgeFIN(id uint32) {
	m.mu.Lock()
	delete(m.pending, id)
	m.mu.Unlock()
}

func (m *Mux) beginFIN(id uint32) error {
	m.mu.Lock()
	if !m.closed && len(m.pending) < m.maxPending() {
		m.pending[id] = &pendingFIN{next: time.Now().Add(m.finRetryInterval())}
	}
	m.mu.Unlock()
	return m.sendControl(id, frameFIN)
}

func (m *Mux) addTombstoneLocked(id uint32, until time.Time) {
	if _, exists := m.tombstones[id]; !exists && len(m.tombstones) >= m.maxTombstones() {
		for evict := range m.tombstones {
			delete(m.tombstones, evict)
			break
		}
	}
	m.tombstones[id] = until
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
	m.pending = make(map[uint32]*pendingFIN)
	m.tombstones = make(map[uint32]time.Time)
	m.mu.Unlock()

	// Outside the lock: shut only touches the flow's own state, but a closer that
	// re-entered the table would deadlock, and this is cheap insurance against that.
	for _, f := range live {
		f.shut(cause)
	}
}

func (m *Mux) stopMaintenance() {
	m.stopOnce.Do(func() {
		close(m.maintStop)
		<-m.maintDone
	})
}

func (m *Mux) maintain() {
	interval := m.finRetryInterval()
	if idle := m.idleTimeout() / 2; idle > 0 && idle < interval {
		interval = idle
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	defer close(m.maintDone)

	for {
		select {
		case <-m.maintStop:
			return
		case now := <-ticker.C:
			m.maintenance(now)
		}
	}
}

func (m *Mux) maintenance(now time.Time) {
	var (
		retry []uint32
		idle  []*flow
	)
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	for id, until := range m.tombstones {
		if !now.Before(until) {
			delete(m.tombstones, id)
		}
	}
	for id, pending := range m.pending {
		if !now.Before(pending.next) {
			if pending.retries >= m.finRetryCount() {
				delete(m.pending, id)
				continue
			}
			pending.retries++
			pending.next = now.Add(m.finRetryInterval())
			retry = append(retry, id)
		}
	}
	for id, f := range m.flows {
		if now.Sub(f.lastActivity) >= m.idleTimeout() {
			delete(m.flows, id)
			// Idle reaping is the last-resort close path when every FIN was lost.
			// Keep the same late-DATA guard as an observed FIN; otherwise a packet
			// delayed past the idle deadline could immediately recreate the peer flow.
			m.addTombstoneLocked(id, now.Add(m.tombstoneTTL()))
			idle = append(idle, f)
			if len(m.pending) < m.maxPending() {
				m.pending[id] = &pendingFIN{next: now.Add(m.finRetryInterval())}
			}
		}
	}
	m.mu.Unlock()

	for _, f := range idle {
		f.shut(net.ErrClosed)
		_ = m.sendControl(f.id, frameFIN)
	}
	for _, id := range retry {
		_ = m.sendControl(id, frameFIN)
	}
}

func (m *Mux) sendControl(id uint32, kind frameKind) error {
	var frame [Header]byte
	binary.BigEndian.PutUint32(frame[:4], id)
	frame[4] = byte(kind)
	return m.sendFrame(frame[:])
}

func (m *Mux) sendFrame(frame []byte) error {
	m.sendMu.Lock()
	defer m.sendMu.Unlock()
	return m.cfg.Send(frame)
}

func (m *Mux) finRetryInterval() time.Duration {
	if m.cfg.FINRetryInterval > 0 {
		return m.cfg.FINRetryInterval
	}
	return defaultFINRetryInterval
}

func (m *Mux) finRetryCount() int {
	if m.cfg.FINRetryCount > 0 {
		return m.cfg.FINRetryCount
	}
	return defaultFINRetryCount
}

func (m *Mux) idleTimeout() time.Duration {
	if m.cfg.IdleTimeout > 0 {
		return m.cfg.IdleTimeout
	}
	return defaultIdleTimeout
}

func (m *Mux) tombstoneTTL() time.Duration {
	if m.cfg.TombstoneTTL > 0 {
		return m.cfg.TombstoneTTL
	}
	return defaultTombstoneTTL
}

func (m *Mux) maxPending() int {
	if m.cfg.MaxPending > 0 {
		return m.cfg.MaxPending
	}
	return defaultMaxPending
}

func (m *Mux) maxTombstones() int {
	if m.cfg.MaxTombstones > 0 {
		return m.cfg.MaxTombstones
	}
	return defaultMaxTombstones
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

	lastActivity time.Time
}

func newFlow(id uint32, m *Mux) *flow {
	return &flow{
		id:           id,
		mux:          m,
		packets:      make(chan []byte, flowQueue),
		closed:       make(chan struct{}),
		lastActivity: time.Now(),
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
	f.mux.touch(f)
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

	// The frame comes from the pool rather than the heap: this is the per-datagram path
	// of both unreliable tiers, and the header has to sit in front of a payload the
	// caller owns, so the copy is unavoidable but the allocation is not. Taking a fresh
	// buffer per call - rather than one scratch buffer per flow - is what keeps this
	// safe without a lock: transport.Stream does not promise a single writer, and two
	// concurrent Writes on one flow would otherwise interleave into the same bytes.
	bufp := framePool.Get().(*[]byte)
	frame := binary.BigEndian.AppendUint32((*bufp)[:0], f.id)
	frame = append(frame, byte(frameData))
	frame = append(frame, payload...)

	// A message the channel cannot carry - a QUIC datagram over the path limit, say -
	// surfaces here rather than being papered over. Splitting the payload would deliver
	// a forwarded datagram the application never sent, and dropping it silently would
	// look like packet loss the peer could not diagnose; failing the flow is the only
	// option that stays honest about what happened.
	err := f.mux.sendFrame(frame)

	// Returned whatever happened, and only after Send has returned: Config.Send is
	// documented not to retain the slice, which is precisely what makes reuse legal
	// here. A grown buffer is kept at its new capacity so a flow carrying large
	// datagrams stops reallocating after the first few.
	*bufp = frame[:0]
	framePool.Put(bufp)

	if err != nil {
		return fmt.Errorf("flowmux: send on flow %d: %w", f.id, err)
	}
	f.mux.touch(f)
	return nil
}

func (m *Mux) touch(f *flow) {
	m.mu.Lock()
	if current, ok := m.flows[f.id]; ok && current == f {
		f.lastActivity = time.Now()
	}
	m.mu.Unlock()
}

// framePool holds frame buffers for send. The initial capacity covers a header plus a
// payload at any MTU either tier can carry, so the steady state neither allocates nor
// grows.
//
// It stores *[]byte rather than []byte because a slice put back into a sync.Pool as an
// interface value allocates its own header every time, which would defeat the point.
var framePool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, Header+2048)
		return &b
	},
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

	return f.mux.beginFIN(f.id)
}
