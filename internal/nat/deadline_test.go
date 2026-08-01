package nat

import (
	"bytes"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// fakeSubstrate stands in for the punched ice.Conn: reads block until the test feeds
// a datagram or closes it, writes are recorded. Like ice.Conn it implements the
// deadline setters as stubs that do nothing, which is the behaviour under test.
type fakeSubstrate struct {
	feed   chan []byte
	closed chan struct{}
	once   sync.Once

	mu      sync.Mutex
	writes  [][]byte
	closals int
}

func newFakeSubstrate() *fakeSubstrate {
	return &fakeSubstrate{feed: make(chan []byte), closed: make(chan struct{})}
}

func (f *fakeSubstrate) Read(p []byte) (int, error) {
	select {
	case msg := <-f.feed:
		return copy(p, msg), nil
	case <-f.closed:
		return 0, net.ErrClosed
	}
}

func (f *fakeSubstrate) Write(p []byte) (int, error) {
	select {
	case <-f.closed:
		return 0, net.ErrClosed
	default:
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes = append(f.writes, bytes.Clone(p))
	return len(p), nil
}

func (f *fakeSubstrate) Close() error {
	f.mu.Lock()
	f.closals++
	f.mu.Unlock()
	f.once.Do(func() { close(f.closed) })
	return nil
}

func (f *fakeSubstrate) sent() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]byte(nil), f.writes...)
}

func (f *fakeSubstrate) closeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closals
}

func (f *fakeSubstrate) LocalAddr() net.Addr              { return nil }
func (f *fakeSubstrate) RemoteAddr() net.Addr             { return nil }
func (f *fakeSubstrate) SetDeadline(time.Time) error      { return nil }
func (f *fakeSubstrate) SetReadDeadline(time.Time) error  { return nil }
func (f *fakeSubstrate) SetWriteDeadline(time.Time) error { return nil }

// send hands one datagram to the pump, failing the test rather than hanging forever.
func (f *fakeSubstrate) send(t *testing.T, msg string) {
	t.Helper()
	select {
	case f.feed <- []byte(msg):
	case <-time.After(2 * time.Second):
		t.Fatalf("pump never read %q from the substrate", msg)
	}
}

func TestDeadlineConnDeliversDatagrams(t *testing.T) {
	t.Parallel()

	sub := newFakeSubstrate()
	c := withDeadlines(sub)
	defer sub.Close()

	sub.send(t, "first")
	sub.send(t, "second")

	for _, want := range []string{"first", "second"} {
		buf := make([]byte, 64)
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		if got := string(buf[:n]); got != want {
			t.Fatalf("Read = %q, want %q", got, want)
		}
	}
}

// A datagram larger than the caller's buffer is truncated and the rest discarded,
// exactly as a UDP socket does. The next Read must return the *next* datagram, not
// the tail of the previous one - a substrate that streamed the remainder instead
// would silently corrupt every consumer's framing.
func TestDeadlineConnTruncatesToBuffer(t *testing.T) {
	t.Parallel()

	sub := newFakeSubstrate()
	c := withDeadlines(sub)
	defer sub.Close()

	sub.send(t, "0123456789")
	sub.send(t, "next")

	small := make([]byte, 4)
	n, err := c.Read(small)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got := string(small[:n]); got != "0123" {
		t.Fatalf("truncated read = %q, want %q", got, "0123")
	}

	buf := make([]byte, 64)
	n, err = c.Read(buf)
	if err != nil {
		t.Fatalf("Read after truncation: %v", err)
	}
	if got := string(buf[:n]); got != "next" {
		t.Fatalf("read after truncation = %q, want %q", got, "next")
	}
}

// The reason this type exists: a read deadline must release the caller, must not
// take the substrate down with it, and must be re-armable afterwards. wireguard-go
// and quic-go both close by setting a deadline in the past and waiting for the read
// loop to return, so all three properties are load-bearing.
func TestDeadlineConnReadDeadlineExpiresWithoutClosingSubstrate(t *testing.T) {
	t.Parallel()

	sub := newFakeSubstrate()
	c := withDeadlines(sub)
	defer sub.Close()

	if err := c.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	start := time.Now()
	if _, err := c.Read(make([]byte, 64)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read err = %v, want os.ErrDeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Read blocked %v past its deadline", elapsed)
	}
	if n := sub.closeCount(); n != 0 {
		t.Fatalf("substrate closed %d times by a deadline; it must survive for the next tier", n)
	}

	// Re-arming after expiry is what a caller extending a lapsed deadline needs, and
	// it is the case a single reused channel would get wrong.
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline (extend): %v", err)
	}
	sub.send(t, "after-deadline")
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("Read after extending the deadline: %v", err)
	}
	if got := string(buf[:n]); got != "after-deadline" {
		t.Fatalf("Read = %q, want %q", got, "after-deadline")
	}
}

func TestDeadlineConnZeroTimeClearsDeadline(t *testing.T) {
	t.Parallel()

	sub := newFakeSubstrate()
	c := withDeadlines(sub)
	defer sub.Close()

	if err := c.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetReadDeadline (past): %v", err)
	}
	if _, err := c.Read(make([]byte, 64)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read with a past deadline = %v, want os.ErrDeadlineExceeded", err)
	}

	if err := c.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("SetReadDeadline (zero): %v", err)
	}
	sub.send(t, "unbounded")
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("Read after clearing the deadline: %v", err)
	}
	if got := string(buf[:n]); got != "unbounded" {
		t.Fatalf("Read = %q, want %q", got, "unbounded")
	}
}

func TestDeadlineConnWriteDeadline(t *testing.T) {
	t.Parallel()

	sub := newFakeSubstrate()
	c := withDeadlines(sub)
	defer sub.Close()

	if _, err := c.Write([]byte("before")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := c.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if _, err := c.Write([]byte("after")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Write past its deadline = %v, want os.ErrDeadlineExceeded", err)
	}

	sent := sub.sent()
	if len(sent) != 1 || string(sent[0]) != "before" {
		t.Fatalf("substrate saw %q, want exactly one write of %q", sent, "before")
	}
}

// A substrate that ends still owes its consumer the datagrams it already accepted:
// reporting the close first would drop them, and both channels being ready at once
// makes that a coin flip without the drain in Read.
func TestDeadlineConnDrainsBeforeReportingClose(t *testing.T) {
	t.Parallel()

	sub := newFakeSubstrate()
	c := withDeadlines(sub)

	sub.send(t, "one")
	sub.send(t, "two")
	sub.Close()

	for _, want := range []string{"one", "two"} {
		buf := make([]byte, 64)
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("Read before the close error: %v", err)
		}
		if got := string(buf[:n]); got != want {
			t.Fatalf("Read = %q, want %q", got, want)
		}
	}
	if _, err := c.Read(make([]byte, 64)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Read after draining = %v, want net.ErrClosed", err)
	}
}

// More datagrams than the buffer pool holds, one at a time: if consume failed to
// return buffers the pump would wedge on an empty free list partway through.
func TestDeadlineConnRecyclesBuffers(t *testing.T) {
	t.Parallel()

	sub := newFakeSubstrate()
	c := withDeadlines(sub)
	defer sub.Close()

	for i := range substrateQueue * 3 {
		msg := string(rune('a' + i%26))
		sub.send(t, msg)
		buf := make([]byte, 64)
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("Read %d: %v", i, err)
		}
		if got := string(buf[:n]); got != msg {
			t.Fatalf("Read %d = %q, want %q", i, got, msg)
		}
	}
}

// Every buffer handed back must be full-length again. Returning the truncated slice
// would shrink the pool one datagram at a time until nothing larger than the last
// short read could arrive.
func TestDeadlineConnRestoresBufferCapacity(t *testing.T) {
	t.Parallel()

	sub := newFakeSubstrate()
	c := withDeadlines(sub)
	defer sub.Close()

	// Drain the pool through a short datagram so every buffer has been recycled once.
	for range substrateQueue {
		sub.send(t, "x")
		if _, err := c.Read(make([]byte, 64)); err != nil {
			t.Fatalf("Read: %v", err)
		}
	}

	large := bytes.Repeat([]byte("z"), substrateMTU)
	select {
	case sub.feed <- large:
	case <-time.After(2 * time.Second):
		t.Fatal("pump never read the full-size datagram")
	}

	buf := make([]byte, substrateMTU)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("Read full-size datagram: %v", err)
	}
	if n != substrateMTU {
		t.Fatalf("Read = %d bytes, want %d: the buffer pool shrank", n, substrateMTU)
	}
}
