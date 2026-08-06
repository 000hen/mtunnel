package flowmux

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"mtunnel-libp2p/internal/transport"
)

const testTimeout = 5 * time.Second

// channel is one end of an in-memory message pipe: whole messages in, whole messages
// out, exactly like the QUIC datagram channel and the virtual UDP conn the real muxes
// run on.
type channel struct {
	inbox  chan []byte
	peer   chan []byte
	closed chan struct{}

	mu      sync.Mutex
	sendErr error
	sent    [][]byte
	drop    func([]byte) bool
}

func newChannelPair() (*channel, *channel) {
	a2b := make(chan []byte, 256)
	b2a := make(chan []byte, 256)
	closed := make(chan struct{})
	return &channel{inbox: b2a, peer: a2b, closed: closed},
		&channel{inbox: a2b, peer: b2a, closed: closed}
}

func (c *channel) send(msg []byte) error {
	c.mu.Lock()
	if c.sendErr != nil {
		err := c.sendErr
		c.mu.Unlock()
		return err
	}
	// The Mux says Send must not retain the slice, so copying here is what makes a
	// violation of that contract show up as a test failure rather than as luck.
	cp := append([]byte(nil), msg...)
	c.sent = append(c.sent, cp)
	drop := c.drop
	c.mu.Unlock()
	if drop != nil && drop(cp) {
		return nil
	}

	select {
	case c.peer <- cp:
		return nil
	case <-c.closed:
		return net.ErrClosed
	}
}

func (c *channel) setDrop(drop func([]byte) bool) {
	c.mu.Lock()
	c.drop = drop
	c.mu.Unlock()
}

func (c *channel) recv() ([]byte, error) {
	select {
	case msg := <-c.inbox:
		return msg, nil
	case <-c.closed:
		return nil, net.ErrClosed
	}
}

func (c *channel) failSends(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sendErr = err
}

func (c *channel) messages() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.sent...)
}

func muxPair(t *testing.T) (dialer, accepter *Mux, dialChan, acceptChan *channel) {
	t.Helper()

	dialChan, acceptChan = newChannelPair()
	dialer = New(Config{Send: dialChan.send, Recv: dialChan.recv, Dialing: true})
	accepter = New(Config{Send: acceptChan.send, Recv: acceptChan.recv})
	t.Cleanup(func() {
		close(dialChan.closed)
		_ = dialer.Close()
		_ = accepter.Close()
	})
	return dialer, accepter, dialChan, acceptChan
}

func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	t.Cleanup(cancel)
	return ctx
}

func TestMuxRoundTrip(t *testing.T) {
	t.Parallel()

	dialer, accepter, _, _ := muxPair(t)
	ctx := testCtx(t)

	local, err := dialer.OpenStream(ctx)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := local.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}

	remote, err := accepter.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}

	buf := make([]byte, 64)
	n, err := remote.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := string(buf[:n]); got != "hello" {
		t.Fatalf("read %q, want %q", got, "hello")
	}

	if _, err := remote.Write([]byte("world")); err != nil {
		t.Fatalf("reply: %v", err)
	}
	n, err = local.Read(buf)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if got := string(buf[:n]); got != "world" {
		t.Fatalf("reply %q, want %q", got, "world")
	}
}

// One message in is one message out - no splicing two together and no fragmenting one
// across reads. Forwarded UDP depends on it: internal/udp's length prefix rides inside
// the payload and a spliced read would frame the wrong bytes.
func TestMuxPreservesMessageBoundaries(t *testing.T) {
	t.Parallel()

	dialer, accepter, _, _ := muxPair(t)
	ctx := testCtx(t)

	local, err := dialer.OpenStream(ctx)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	messages := [][]byte{
		[]byte("a"),
		bytes.Repeat([]byte("z"), 1200),
		[]byte("tail"),
	}
	for _, msg := range messages {
		if _, err := local.Write(msg); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	remote, err := accepter.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	buf := make([]byte, 4096)
	for i, want := range messages {
		n, err := remote.Read(buf)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if !bytes.Equal(buf[:n], want) {
			t.Fatalf("message %d: got %d bytes, want %d", i, n, len(want))
		}
	}
}

func TestMuxFlowsAreIndependent(t *testing.T) {
	t.Parallel()

	dialer, accepter, _, _ := muxPair(t)
	ctx := testCtx(t)

	const flows = 6
	local := make([]transport.Stream, flows)
	for i := range local {
		s, err := dialer.OpenStream(ctx)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		local[i] = s
	}

	// Write on every flow before accepting any, so the receive loop has to sort a
	// backlog rather than see them one at a time.
	for i, s := range local {
		if _, err := s.Write([]byte{byte(i)}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	// Accepted order follows arrival order, and arrival order is the write order above.
	buf := make([]byte, 8)
	for i := range flows {
		remote, err := accepter.AcceptStream(ctx)
		if err != nil {
			t.Fatalf("accept %d: %v", i, err)
		}
		n, err := remote.Read(buf)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if n != 1 || buf[0] != byte(i) {
			t.Fatalf("flow %d received %v, want [%d]", i, buf[:n], i)
		}
		// Replying proves the accepted stream is bound to the right flow ID: a reply
		// on the wrong one would reach the wrong local stream below.
		if _, err := remote.Write([]byte{byte(100 + i)}); err != nil {
			t.Fatalf("reply %d: %v", i, err)
		}
	}

	for i, s := range local {
		n, err := s.Read(buf)
		if err != nil {
			t.Fatalf("read reply %d: %v", i, err)
		}
		if n != 1 || buf[0] != byte(100+i) {
			t.Fatalf("flow %d reply %v, want [%d]", i, buf[:n], 100+i)
		}
	}
}

// IDs are namespaced by role so both sides could open flows without colliding. Only
// the client does today, which is exactly why this is worth asserting: nothing else
// would notice the namespacing breaking.
func TestMuxNamespacesFlowIDsByRole(t *testing.T) {
	t.Parallel()

	dialer, accepter, dialChan, acceptChan := muxPair(t)
	ctx := testCtx(t)

	ids := func(c *channel) []uint32 {
		var out []uint32
		for _, msg := range c.messages() {
			out = append(out, binary.BigEndian.Uint32(msg[:Header]))
		}
		return out
	}

	for i := range 3 {
		s, err := dialer.OpenStream(ctx)
		if err != nil {
			t.Fatalf("dialer open %d: %v", i, err)
		}
		if _, err := s.Write([]byte("x")); err != nil {
			t.Fatalf("dialer write %d: %v", i, err)
		}
	}
	for i := range 3 {
		s, err := accepter.OpenStream(ctx)
		if err != nil {
			t.Fatalf("accepter open %d: %v", i, err)
		}
		if _, err := s.Write([]byte("x")); err != nil {
			t.Fatalf("accepter write %d: %v", i, err)
		}
	}

	if got, want := ids(dialChan), []uint32{0, 2, 4}; !equalIDs(got, want) {
		t.Fatalf("dialer flow IDs %v, want %v", got, want)
	}
	if got, want := ids(acceptChan), []uint32{1, 3, 5}; !equalIDs(got, want) {
		t.Fatalf("accepter flow IDs %v, want %v", got, want)
	}
}

func equalIDs(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Closing a flow has to reach the peer. Without the FIN the far end would hold a
// forwarded local connection open until something else eventually noticed - and for
// UDP, nothing else would.
func TestMuxCloseSendsFIN(t *testing.T) {
	t.Parallel()

	dialer, accepter, dialChan, _ := muxPair(t)
	ctx := testCtx(t)

	local, err := dialer.OpenStream(ctx)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := local.Write([]byte("data")); err != nil {
		t.Fatalf("write: %v", err)
	}
	remote, err := accepter.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	buf := make([]byte, 64)
	if _, err := remote.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}

	if err := local.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if _, err := remote.Read(buf); !errors.Is(err, io.EOF) {
		t.Fatalf("read after peer close = %v, want io.EOF", err)
	}

	sent := dialChan.messages()
	last := sent[len(sent)-1]
	if len(last) != Header {
		t.Fatalf("last message was %d bytes, want a bare %d-byte FIN", len(last), Header)
	}
}

// A FIN for a flow nobody knows about must be ignored, not treated as the start of a
// new one - otherwise a late FIN would resurrect the flow it was ending.
func TestMuxStrayFINDoesNotOpenAFlow(t *testing.T) {
	t.Parallel()

	_, accepter, dialChan, _ := muxPair(t)

	var fin [Header]byte
	binary.BigEndian.PutUint32(fin[:], 4242)
	if err := dialChan.send(fin[:]); err != nil {
		t.Fatalf("send stray FIN: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := accepter.AcceptStream(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("AcceptStream after a stray FIN = %v, want the accept to keep waiting", err)
	}
}

func TestMuxDropsUnaddressableMessages(t *testing.T) {
	t.Parallel()

	_, accepter, dialChan, _ := muxPair(t)

	// Too short to carry a flow ID at all.
	for _, msg := range [][]byte{{}, {1}, {1, 2, 3}} {
		if err := dialChan.send(msg); err != nil {
			t.Fatalf("send: %v", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := accepter.AcceptStream(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("AcceptStream = %v, want the runt messages to have been dropped", err)
	}

	// The receive loop must still be running afterwards. The ID is even because the
	// sender here is the dialling side, and only that half of the space may open a
	// flow on the accepter - see lookupOrCreate.
	frame := make([]byte, Header+1)
	binary.BigEndian.PutUint32(frame[:Header], 8)
	frame[Header] = 'k'
	if err := dialChan.send(frame); err != nil {
		t.Fatalf("send: %v", err)
	}
	if _, err := accepter.AcceptStream(testCtx(t)); err != nil {
		t.Fatalf("accept after runt messages: %v", err)
	}
}

// A flow nobody accepts must be discarded rather than accumulate, and the drop has to
// be reported: a silently discarded connection is indistinguishable from one that
// never arrived.
func TestMuxDropsFlowsWhenNobodyAccepts(t *testing.T) {
	t.Parallel()

	dialChan, acceptChan := newChannelPair()
	defer close(dialChan.closed)

	var (
		mu      sync.Mutex
		dropped []uint32
	)
	accepter := New(Config{
		Send: acceptChan.send,
		Recv: acceptChan.recv,
		OnDrop: func(id uint32, _ string) {
			mu.Lock()
			defer mu.Unlock()
			dropped = append(dropped, id)
		},
	})
	defer accepter.Close()

	// One more flow than the backlog can hold, none of them accepted.
	for id := range uint32(inboundBacklog + 8) {
		frame := make([]byte, Header+1)
		binary.BigEndian.PutUint32(frame[:Header], id*2)
		frame[Header] = 'x'
		if err := dialChan.send(frame); err != nil {
			t.Fatalf("send %d: %v", id, err)
		}
	}

	deadline := time.Now().Add(testTimeout)
	for {
		mu.Lock()
		n := len(dropped)
		mu.Unlock()
		if n >= 8 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d flows were dropped; the backlog should have overflowed", n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestMuxSendErrorSurfaces(t *testing.T) {
	t.Parallel()

	dialer, _, dialChan, _ := muxPair(t)
	ctx := testCtx(t)

	local, err := dialer.OpenStream(ctx)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	sendErr := errors.New("datagram too large")
	dialChan.failSends(sendErr)

	// The error must reach the caller rather than be swallowed: a forwarded datagram
	// silently dropped here looks like packet loss the peer cannot diagnose.
	if _, err := local.Write([]byte("payload")); !errors.Is(err, sendErr) {
		t.Fatalf("write = %v, want it to wrap %v", err, sendErr)
	}
}

func TestMuxCloseEndsLiveFlows(t *testing.T) {
	t.Parallel()

	dialer, _, _, _ := muxPair(t)
	ctx := testCtx(t)

	local, err := dialer.OpenStream(ctx)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	blocked := make(chan error, 1)
	go func() {
		buf := make([]byte, 64)
		_, err := local.Read(buf)
		blocked <- err
	}()

	// Let the read actually park before closing under it.
	time.Sleep(20 * time.Millisecond)
	if err := dialer.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	select {
	case err := <-blocked:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("blocked read = %v, want net.ErrClosed", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("Close left a reader blocked")
	}

	if _, err := dialer.OpenStream(ctx); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("OpenStream after Close = %v, want net.ErrClosed", err)
	}
}

// When the channel underneath dies, everything riding on it has to learn - both live
// flows and anyone parked on an accept.
func TestMuxChannelFailureUnblocksEveryone(t *testing.T) {
	t.Parallel()

	dialChan, acceptChan := newChannelPair()
	dialer := New(Config{Send: dialChan.send, Recv: dialChan.recv, Dialing: true})
	accepter := New(Config{Send: acceptChan.send, Recv: acceptChan.recv})
	defer dialer.Close()
	defer accepter.Close()

	ctx := testCtx(t)
	local, err := dialer.OpenStream(ctx)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	reads := make(chan error, 1)
	go func() {
		buf := make([]byte, 64)
		_, err := local.Read(buf)
		reads <- err
	}()
	accepts := make(chan error, 1)
	go func() {
		_, err := accepter.AcceptStream(context.Background())
		accepts <- err
	}()

	time.Sleep(20 * time.Millisecond)
	close(dialChan.closed) // both ends share the channel's closed signal

	for name, ch := range map[string]chan error{"read": reads, "accept": accepts} {
		select {
		case err := <-ch:
			if err == nil {
				t.Fatalf("%s returned success after the channel died", name)
			}
		case <-time.After(testTimeout):
			t.Fatalf("%s never returned after the channel died", name)
		}
	}

	select {
	case <-dialer.Done():
	case <-time.After(testTimeout):
		t.Fatal("Done never closed after the channel died")
	}
}

func TestMuxCloseIsIdempotent(t *testing.T) {
	t.Parallel()

	dialer, _, _, _ := muxPair(t)
	for i := range 3 {
		if err := dialer.Close(); err != nil {
			t.Fatalf("close %d: %v", i, err)
		}
	}
}

// The ID namespace split is an invariant, not a convention: a peer that creates a
// flow in this side's half would have it silently replaced the moment OpenStream
// reached that ID, leaving two streams stamped identically on the wire.
func TestMuxRejectsFlowInLocalNamespace(t *testing.T) {
	t.Parallel()

	dialChan, acceptChan := newChannelPair()
	defer close(dialChan.closed)

	var (
		mu      sync.Mutex
		dropped []uint32
	)
	dialer := New(Config{
		Send:    dialChan.send,
		Recv:    dialChan.recv,
		Dialing: true,
		OnDrop: func(id uint32, _ string) {
			mu.Lock()
			defer mu.Unlock()
			dropped = append(dropped, id)
		},
	})
	defer func() { _ = dialer.Close() }()

	// 0 is the dialling side's own first ID, so the peer must not be able to open a
	// flow there.
	frame := make([]byte, Header+1)
	binary.BigEndian.PutUint32(frame[:Header], 0)
	frame[Header] = 'x'
	if err := acceptChan.send(frame); err != nil {
		t.Fatalf("send: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := dialer.AcceptStream(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("AcceptStream = %v, want the local-namespace flow to have been refused", err)
	}
	mu.Lock()
	got := append([]uint32(nil), dropped...)
	mu.Unlock()
	if len(got) != 1 || got[0] != 0 {
		t.Fatalf("dropped = %v, want exactly [0]", got)
	}

	// The ID must still be usable by this side afterwards, with nothing stale left
	// behind for it to collide with.
	s, err := dialer.OpenStream(testCtx(t))
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	if _, err := s.Write([]byte("hi")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	sent := dialChan.messages()
	if len(sent) != 1 {
		t.Fatalf("sent %d messages, want 1", len(sent))
	}
	if id := binary.BigEndian.Uint32(sent[0][:Header]); id != 0 {
		t.Fatalf("OpenStream used flow ID %d, want 0", id)
	}
}

func controlFrame(id uint32, kind frameKind) []byte {
	frame := make([]byte, Header)
	binary.BigEndian.PutUint32(frame[:4], id)
	frame[4] = byte(kind)
	return frame
}

func dataFrame(id uint32, payload []byte) []byte {
	frame := controlFrame(id, frameData)
	return append(frame, payload...)
}

func testReliableConfig(c *channel, dialing bool) Config {
	return Config{
		Send:             c.send,
		Recv:             c.recv,
		Dialing:          dialing,
		FINRetryInterval: time.Hour,
		FINRetryCount:    2,
		IdleTimeout:      time.Hour,
		TombstoneTTL:     time.Hour,
	}
}

func TestMuxRetriesLostFIN(t *testing.T) {
	dialChan, acceptChan := newChannelPair()
	dialer := New(testReliableConfig(dialChan, true))
	accepter := New(testReliableConfig(acceptChan, false))
	t.Cleanup(func() {
		close(dialChan.closed)
		_ = dialer.Close()
		_ = accepter.Close()
	})

	dialChan.setDrop(func(frame []byte) bool {
		return len(frame) == Header && frame[4] == byte(frameFIN)
	})

	local, err := dialer.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	remote, fresh := accepter.lookupOrCreate(0)
	if remote == nil || !fresh {
		t.Fatal("create peer flow")
	}
	if err := local.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	dialer.maintenance(time.Now().Add(2 * time.Hour))
	if got := len(dialChan.messages()); got != 2 {
		t.Fatalf("FIN sends = %d, want initial send plus one retry", got)
	}
	accepter.handle(controlFrame(0, frameFIN))
	if _, err := remote.recv(); !errors.Is(err, io.EOF) {
		t.Fatalf("remote after retried FIN = %v, want io.EOF", err)
	}
}

func TestFlowCloseReportsInitialFINSendError(t *testing.T) {
	t.Parallel()

	want := errors.New("send FIN")
	releaseRecv := make(chan struct{})
	mux := New(Config{
		Dialing: true,
		Send: func([]byte) error {
			return want
		},
		Recv: func() ([]byte, error) {
			<-releaseRecv
			return nil, net.ErrClosed
		},
	})

	stream, err := mux.OpenStream(t.Context())
	if err != nil {
		t.Fatalf("OpenStream() error = %v", err)
	}
	if err := stream.Close(); !errors.Is(err, want) {
		t.Fatalf("Close() error = %v, want %v", err, want)
	}

	close(releaseRecv)
	<-mux.Done()
}

func TestMuxDuplicateFINRetriesUntilACK(t *testing.T) {
	dialChan, acceptChan := newChannelPair()
	dialer := New(testReliableConfig(dialChan, true))
	accepter := New(testReliableConfig(acceptChan, false))
	t.Cleanup(func() {
		close(dialChan.closed)
		_ = dialer.Close()
		_ = accepter.Close()
	})

	acceptChan.setDrop(func(frame []byte) bool {
		return len(frame) == Header && frame[4] == byte(frameFINAck)
	})
	dialChan.setDrop(func(frame []byte) bool {
		return len(frame) == Header && frame[4] == byte(frameFIN)
	})

	local, err := dialer.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	remote, _ := accepter.lookupOrCreate(0)
	if err := local.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	accepter.handle(controlFrame(0, frameFIN))
	if _, err := remote.recv(); !errors.Is(err, io.EOF) {
		t.Fatalf("remote after initial FIN = %v, want io.EOF", err)
	}

	dialer.maintenance(time.Now().Add(2 * time.Hour))
	accepter.handle(controlFrame(0, frameFIN))
	dialer.handle(controlFrame(0, frameFINAck))
	dialer.mu.Lock()
	_, pending := dialer.pending[0]
	dialer.mu.Unlock()
	if pending {
		t.Fatal("duplicate FIN ACK did not clear pending teardown")
	}
}

func TestMuxFINTombstoneDropsLateData(t *testing.T) {
	dialChan, acceptChan := newChannelPair()
	accepter := New(testReliableConfig(acceptChan, false))
	t.Cleanup(func() {
		close(dialChan.closed)
		_ = accepter.Close()
	})

	accepter.handle(controlFrame(42, frameFIN))
	accepter.handle(dataFrame(42, []byte("late")))

	accepter.mu.Lock()
	_, live := accepter.flows[42]
	_, tombstoned := accepter.tombstones[42]
	accepter.mu.Unlock()
	if live || !tombstoned {
		t.Fatalf("late DATA after FIN: live=%v tombstoned=%v", live, tombstoned)
	}
}

func TestMuxIdleReapsWhenAllFINsAreLost(t *testing.T) {
	dialChan, acceptChan := newChannelPair()
	dialChan.setDrop(func(frame []byte) bool {
		return len(frame) == Header && frame[4] == byte(frameFIN)
	})
	dialer := New(testReliableConfig(dialChan, true))
	accepter := New(testReliableConfig(acceptChan, false))
	t.Cleanup(func() {
		close(dialChan.closed)
		_ = dialer.Close()
		_ = accepter.Close()
	})

	local, err := dialer.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	remote, _ := accepter.lookupOrCreate(0)
	then := time.Now().Add(2 * time.Hour)
	dialer.maintenance(then)
	accepter.maintenance(then)
	if _, err := local.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("local after idle reap = %v, want net.ErrClosed", err)
	}
	if _, err := remote.recv(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("remote after idle reap = %v, want net.ErrClosed", err)
	}

	accepter.handle(dataFrame(0, []byte("late")))
	accepter.mu.Lock()
	_, resurrected := accepter.flows[0]
	_, tombstoned := accepter.tombstones[0]
	accepter.mu.Unlock()
	if resurrected || !tombstoned {
		t.Fatalf("late DATA after idle reap: live=%v tombstoned=%v", resurrected, tombstoned)
	}
}

func TestMuxCloseStopsMaintenance(t *testing.T) {
	dialChan, _ := newChannelPair()
	mux := New(testReliableConfig(dialChan, true))
	close(dialChan.closed)
	if err := mux.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case <-mux.maintDone:
	default:
		t.Fatal("Close returned before the maintenance loop stopped")
	}
}
