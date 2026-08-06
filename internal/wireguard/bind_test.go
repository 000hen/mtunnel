package wireguard

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// timeoutError is what a real net.Conn reports when a read deadline expires.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// fakeConn is a net.Conn whose reads a test drives directly, so every ordering that
// matters to Bind - a read unblocked by Close, a foreign deadline, a substrate error
// - can be produced deliberately rather than waited for.
type fakeConn struct {
	reads chan []byte
	errs  chan error

	// reading is signalled as a Read is entered, i.e. once it is past the point
	// where Bind's receive could still notice the close on its own. Tests that need
	// the receive genuinely parked in the substrate - the ordering Close's fallback
	// exists for - wait on this rather than sleeping: a sleep only makes that
	// ordering likely, and a loaded machine that misses the window turns the case
	// under test into the case that was already passing.
	reading chan struct{}

	mu       sync.Mutex
	writes   [][]byte
	closes   int
	deadline chan struct{}
	gone     chan struct{}
	// deadlineErr makes SetReadDeadline fail, which is how Bind's last-resort path
	// (close the substrate rather than hang) gets exercised.
	deadlineErr error
	// deadlineStub makes SetReadDeadline succeed without doing anything, which is
	// what pion/ice's Conn does and the reason Bind cannot trust a nil error.
	deadlineStub bool
	// deadlines records every value SetReadDeadline was handed, in order, so a test
	// can assert what the substrate is left holding once Bind is done with it.
	deadlines []time.Time
	remote    net.Addr
}

func newFakeConn() *fakeConn {
	return &fakeConn{
		reads:    make(chan []byte),
		errs:     make(chan error),
		reading:  make(chan struct{}, 1),
		deadline: make(chan struct{}),
		gone:     make(chan struct{}),
		remote:   &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 51820},
	}
}

func (c *fakeConn) Read(p []byte) (int, error) {
	// Buffered and non-blocking, so a Read entered before anyone is waiting still
	// records that it happened and a test that never waits is not held up by one.
	select {
	case c.reading <- struct{}{}:
	default:
	}

	select {
	case b, ok := <-c.reads:
		if !ok {
			return 0, io.EOF
		}
		return copy(p, b), nil
	case err := <-c.errs:
		return 0, err
	case <-c.deadline:
		return 0, timeoutError{}
	case <-c.gone:
		return 0, net.ErrClosed
	}
}

func (c *fakeConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.writes = append(c.writes, append([]byte(nil), p...))
	return len(p), nil
}

func (c *fakeConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.closes++
	select {
	case <-c.gone:
	default:
		close(c.gone)
	}
	return nil
}

func (c *fakeConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	if c.deadlineErr != nil {
		err := c.deadlineErr
		c.mu.Unlock()
		return err
	}
	c.deadlines = append(c.deadlines, t)
	stub := c.deadlineStub
	c.mu.Unlock()

	// A stub accepts the deadline and forgets it, exactly as pion/ice's Conn does.
	if stub {
		return nil
	}
	// The zero time clears the deadline rather than setting one, so it must not
	// expire a read. Bind only ever sets these two values.
	if t.IsZero() {
		return nil
	}

	// Only the expired-deadline case matters here, and Bind only ever sets one.
	select {
	case <-c.deadline:
	default:
		close(c.deadline)
	}
	return nil
}

func (c *fakeConn) closeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.closes
}

// lastReadDeadline reports the deadline the substrate is left holding, and whether
// one was ever set.
func (c *fakeConn) lastReadDeadline() (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.deadlines) == 0 {
		return time.Time{}, false
	}
	return c.deadlines[len(c.deadlines)-1], true
}

func (c *fakeConn) written() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.writes
}

func (c *fakeConn) LocalAddr() net.Addr              { return c.remote }
func (c *fakeConn) RemoteAddr() net.Addr             { return c.remote }
func (c *fakeConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }

var _ net.Conn = (*fakeConn)(nil)

// receiveOnce runs one ReceiveFunc on its own goroutine and reports what it produced.
type received struct {
	n   int
	pkt []byte
	ep  conn.Endpoint
	err error
}

func receiveOnce(recv conn.ReceiveFunc) <-chan received {
	out := make(chan received, 1)
	go func() {
		packets := [][]byte{make([]byte, 1500)}
		sizes := make([]int, 1)
		eps := make([]conn.Endpoint, 1)
		n, err := recv(packets, sizes, eps)
		r := received{n: n, ep: eps[0], err: err}
		if err == nil && n > 0 {
			r.pkt = packets[0][:sizes[0]]
		}
		out <- r
	}()
	return out
}

// awaitReading blocks until the substrate has a Read in flight, which is the state
// Bind's receive loop has to be in for a test to exercise how Close gets it out.
func (c *fakeConn) awaitReading(t *testing.T) {
	t.Helper()
	select {
	case <-c.reading:
	case <-time.After(5 * time.Second):
		t.Fatal("receive never reached the substrate")
	}
}

func await(t *testing.T, out <-chan received) received {
	t.Helper()
	select {
	case r := <-out:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("receive did not return")
		return received{}
	}
}

func openBind(t *testing.T, b *Bind) conn.ReceiveFunc {
	t.Helper()
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(fns) != 1 {
		t.Fatalf("Open returned %d receive functions, want 1", len(fns))
	}
	return fns[0]
}

// TestBindCloseBeforeOpenIsNoOp guards the invariant that makes the whole tier work:
// device.Up calls BindUpdate, which closes any previous bind unconditionally before
// opening this one. A Close that latched shut permanently would make every device
// built on this Bind fail to come up.
func TestBindCloseBeforeOpenIsNoOp(t *testing.T) {
	t.Parallel()
	substrate := newFakeConn()
	b := NewBind(substrate)

	if err := b.Close(); err != nil {
		t.Fatalf("Close before Open: %v", err)
	}
	recv := openBind(t, b)

	out := receiveOnce(recv)
	substrate.reads <- []byte("packet")
	got := await(t, out)
	if got.err != nil {
		t.Fatalf("receive after close-then-open: %v", got.err)
	}
	if string(got.pkt) != "packet" {
		t.Errorf("received %q, want %q", got.pkt, "packet")
	}
}

func TestBindDoubleOpen(t *testing.T) {
	t.Parallel()
	b := NewBind(newFakeConn())

	openBind(t, b)
	if _, _, err := b.Open(0); !errors.Is(err, conn.ErrBindAlreadyOpen) {
		t.Fatalf("second Open error = %v, want %v", err, conn.ErrBindAlreadyOpen)
	}
}

// TestBindCloseUnblocksReceive covers what device.Close depends on: it calls
// Bind.Close and then waits for the receive goroutines, so a receive still parked in
// a substrate Read has to be released or shutdown hangs forever.
func TestBindCloseUnblocksReceive(t *testing.T) {
	t.Parallel()
	substrate := newFakeConn()
	b := NewBind(substrate)
	recv := openBind(t, b)

	out := receiveOnce(recv)
	// Let the receive reach its blocking Read before closing, which is the ordering
	// that actually hangs if Close only sets a flag.
	substrate.awaitReading(t)
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	got := await(t, out)
	if !errors.Is(got.err, net.ErrClosed) {
		t.Fatalf("receive error after Close = %v, want %v", got.err, net.ErrClosed)
	}
	if n := substrate.closeCount(); n != 0 {
		t.Errorf("Close closed the substrate %d times; the ICE agent owns it", n)
	}
}

// TestBindCloseRestoresReadDeadline is the regression test for the cascade's second
// rung. Close releases the receive with a deadline in the past, but the substrate is
// shared: it outlives this bind and carries QUIC next. A deadline left expired would
// fail every read that tier makes, turning "WireGuard did not come up" into "nothing
// after WireGuard can come up either" - a fallback that looks like it ran and could
// never have worked.
func TestBindCloseRestoresReadDeadline(t *testing.T) {
	t.Parallel()
	substrate := newFakeConn()
	b := NewBind(substrate)
	recv := openBind(t, b)

	out := receiveOnce(recv)
	// As in TestBindCloseUnblocksReceive: reach the blocking Read first, so Close
	// takes the path that actually sets a deadline.
	substrate.awaitReading(t)
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := await(t, out); !errors.Is(got.err, net.ErrClosed) {
		t.Fatalf("receive error after Close = %v, want %v", got.err, net.ErrClosed)
	}

	last, ok := substrate.lastReadDeadline()
	if !ok {
		t.Fatal("Close set no read deadline at all")
	}
	if !last.IsZero() {
		t.Errorf("substrate left holding read deadline %v, want it cleared", last)
	}
	if n := substrate.closeCount(); n != 0 {
		t.Errorf("Close closed the substrate %d times; the next tier still needs it", n)
	}
}

// TestBindCloseFallsBackToClosingSubstrate covers the one case where Bind gives up
// its hands-off stance: a substrate whose deadlines do not work leaves no other way
// to release the receive, and a leaked conn beats a shutdown that never returns.
//
// It must also say so. The substrate is shared with rungs this package knows nothing
// about, and silence here is what let the failure present as "the next tier did not work
// either" instead of "there was no longer anything for it to work on".
func TestBindCloseFallsBackToClosingSubstrate(t *testing.T) {
	t.Parallel()
	substrate := newFakeConn()
	substrate.deadlineErr = errors.New("deadlines unsupported")
	b := NewBind(substrate)
	openBind(t, b)

	if err := b.Close(); !errors.Is(err, ErrSubstrateAbandoned) {
		t.Fatalf("Close = %v, want %v", err, ErrSubstrateAbandoned)
	}
	if n := substrate.closeCount(); n != 1 {
		t.Errorf("substrate closed %d times, want 1", n)
	}
	if !b.Abandoned() {
		t.Error("Abandoned = false after Close closed the substrate; Tunnel.Close has no other way to find out")
	}
}

// TestBindCloseSurvivesStubbedDeadlines is the regression test for the substrate this
// tier actually runs on. pion/ice's Conn accepts SetReadDeadline, returns nil, and
// ignores it, so a Bind that trusted that nil left its receive parked in Read - and
// device.Close, which waits for exactly that goroutine, hung for good. Closing the
// substrate is the fallback; taking it at all is the behaviour under test.
func TestBindCloseSurvivesStubbedDeadlines(t *testing.T) {
	t.Parallel()
	substrate := newFakeConn()
	substrate.deadlineStub = true
	b := NewBind(substrate)
	recv := openBind(t, b)

	out := receiveOnce(recv)
	// As in TestBindCloseUnblocksReceive: the receive has to be parked inside Read
	// before Close runs, or the case that hangs is never reached - and here that
	// would not fail the test, it would quietly pass it against the wrong path.
	substrate.awaitReading(t)

	done := make(chan error, 1)
	go func() { done <- b.Close() }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrSubstrateAbandoned) {
			t.Fatalf("Close = %v, want %v", err, ErrSubstrateAbandoned)
		}
	// Comfortably above closeGrace, which is what this case is waiting out. The
	// distinction the bound draws is between a Close that gave up on schedule and one
	// that never returns at all.
	case <-time.After(closeGrace + 5*time.Second):
		t.Fatal("Close never returned; device.Close would hang here")
	}

	if n := substrate.closeCount(); n != 1 {
		t.Errorf("substrate closed %d times, want 1: nothing else can release the receive", n)
	}
	got := await(t, out)
	if !errors.Is(got.err, net.ErrClosed) {
		t.Fatalf("receive error after Close = %v, want %v", got.err, net.ErrClosed)
	}
}

// TestBindReceiveIgnoresForeignTimeout pins the difference between a deadline this
// package set (a close, and the device should stop) and one it did not (a healthy
// substrate, and the device should keep receiving).
func TestBindReceiveIgnoresForeignTimeout(t *testing.T) {
	t.Parallel()
	substrate := newFakeConn()
	b := NewBind(substrate)
	recv := openBind(t, b)

	out := receiveOnce(recv)
	substrate.errs <- timeoutError{}
	substrate.reads <- []byte("after the timeout")

	got := await(t, out)
	if got.err != nil {
		t.Fatalf("receive gave up on a foreign timeout: %v", got.err)
	}
	if string(got.pkt) != "after the timeout" {
		t.Errorf("received %q, want %q", got.pkt, "after the timeout")
	}
}

func TestBindReceiveReportsSubstrateError(t *testing.T) {
	t.Parallel()
	substrate := newFakeConn()
	b := NewBind(substrate)
	recv := openBind(t, b)

	failure := errors.New("substrate is gone")
	out := receiveOnce(recv)
	substrate.errs <- failure

	got := await(t, out)
	if !errors.Is(got.err, failure) {
		t.Fatalf("receive error = %v, want it to wrap %v", got.err, failure)
	}
}

func TestBindSendWritesEveryPacket(t *testing.T) {
	t.Parallel()
	substrate := newFakeConn()
	b := NewBind(substrate)

	// A nil endpoint proves Send never consults the one it is handed: with a
	// connected substrate there is only one place a packet can go.
	if err := b.Send([][]byte{[]byte("one"), []byte("two")}, nil); err != nil {
		t.Fatalf("Send: %v", err)
	}
	got := substrate.written()
	if len(got) != 2 || string(got[0]) != "one" || string(got[1]) != "two" {
		t.Errorf("substrate saw %q, want [one two]", got)
	}
}

func TestBindEndpoint(t *testing.T) {
	t.Parallel()
	b := NewBind(newFakeConn())

	ep := b.Endpoint()
	if got, want := ep.DstToString(), "127.0.0.1:51820"; got != want {
		t.Errorf("DstToString = %q, want %q", got, want)
	}
	if got, want := ep.DstIP(), netip.MustParseAddr("127.0.0.1"); got != want {
		t.Errorf("DstIP = %v, want %v", got, want)
	}
	// The UAPI endpoint= line is rendered from Endpoint and resolved back by
	// ParseEndpoint; the round trip has to land on the same endpoint or the device
	// would route to something the substrate cannot reach.
	parsed, err := b.ParseEndpoint(ep.DstToString())
	if err != nil {
		t.Fatalf("ParseEndpoint: %v", err)
	}
	if parsed != ep {
		t.Errorf("ParseEndpoint round trip = %v, want %v", parsed, ep)
	}
	// The argument is deliberately ignored: with one possible destination, a name
	// cannot change where packets go.
	other, err := b.ParseEndpoint("203.0.113.9:1234")
	if err != nil {
		t.Fatalf("ParseEndpoint: %v", err)
	}
	if other != ep {
		t.Errorf("ParseEndpoint(%q) = %v, want the substrate's endpoint %v", "203.0.113.9:1234", other, ep)
	}
	if len(ep.DstToBytes()) == 0 {
		t.Error("DstToBytes returned nothing; mac2 cookie calculation needs a stable value")
	}
}

// TestRemoteAddrPortDegrades covers the decision that an unusable peer address is
// bookkeeping noise rather than a tier failure: every send goes to the connected
// substrate whatever the endpoint says.
func TestRemoteAddrPortDegrades(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		remote net.Addr
	}{
		{name: "no address", remote: nil},
		{name: "unparseable address", remote: &net.UnixAddr{Name: "/tmp/x", Net: "unixgram"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			substrate := newFakeConn()
			substrate.remote = tt.remote
			if got := remoteAddrPort(substrate); got.IsValid() {
				t.Errorf("remoteAddrPort = %v, want the zero value", got)
			}
			// Still usable: Send must not depend on a resolvable address.
			if err := NewBind(substrate).Send([][]byte{[]byte("x")}, nil); err != nil {
				t.Errorf("Send with an unresolvable peer address: %v", err)
			}
		})
	}
}
