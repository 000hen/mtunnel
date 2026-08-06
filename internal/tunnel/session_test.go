package tunnel

import (
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"mtunnel-libp2p/internal/control"
	"mtunnel-libp2p/internal/negotiate"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// fakeNetwork stands in for libp2p's network. It embeds the interface so only the two
// methods SessionManager actually calls need implementing; anything else would panic
// on the nil embedded value, which is the point - a new call site should be a visible
// failure rather than a silent nil result.
type fakeNetwork struct {
	network.Network

	mu     sync.Mutex
	closed []peer.ID
}

func (n *fakeNetwork) ConnsToPeer(peer.ID) []network.Conn { return nil }

func (n *fakeNetwork) ClosePeer(id peer.ID) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.closed = append(n.closed, id)
	return nil
}

// fakeConn is the minimum of network.Conn that BeginStream touches.
type fakeConn struct {
	network.Conn
}

func (fakeConn) RemoteMultiaddr() multiaddr.Multiaddr {
	return multiaddr.StringCast("/ip4/198.51.100.7/udp/4001/quic-v1")
}

// events collects what the manager emitted, decoded back from the wire so the test
// sees exactly what an external supervisor would.
type events struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (e *events) Write(p []byte) (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.buf.Write(p)
}

func (e *events) decoded(t *testing.T) []control.Output {
	t.Helper()
	e.mu.Lock()
	raw := e.buf.String()
	e.mu.Unlock()

	var out []control.Output
	dec := json.NewDecoder(strings.NewReader(raw))
	for {
		var o control.Output
		if err := dec.Decode(&o); err != nil {
			if err == io.EOF {
				return out
			}
			t.Fatalf("decode emitted event: %v", err)
		}
		out = append(out, o)
	}
}

func newTestManager(t *testing.T) (*SessionManager, *fakeNetwork, *events) {
	t.Helper()
	net := &fakeNetwork{}
	ev := &events{}
	return NewSessionManager(net, control.NewEmitter(ev)), net, ev
}

func testPeer(t *testing.T) peer.ID {
	t.Helper()
	id, err := peer.Decode("12D3KooWGRUMDGgZgHqZzHqf4dcNBHKPHqXhz9YsHKGHwHhkYFHb")
	if err != nil {
		t.Fatalf("decode peer ID: %v", err)
	}
	return id
}

// TestBeginStreamReportsRegisteredTier covers what the CONNECTED event tells an
// operator: the tier its traffic actually rides, not the floor it would have used.
func TestBeginStreamReportsRegisteredTier(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		register bool
		want     negotiate.Tier
	}{
		// No registration is itself the answer: libp2p is the tier whose streams
		// arrive with nothing else set up.
		{name: "unregistered peer reports the floor", register: false, want: negotiate.TierLibp2p},
		{name: "registered peer reports its tier", register: true, want: negotiate.TierWireGuard},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sm, _, ev := newTestManager(t)
			id := testPeer(t)

			if tt.register {
				sm.RegisterTier(id, negotiate.TierWireGuard, func() {})
			}
			if !sm.BeginStream(id, fakeConn{}) {
				t.Fatal("BeginStream refused a stream on a live manager")
			}
			defer sm.EndStream(id)

			emitted := ev.decoded(t)
			if len(emitted) != 1 || emitted[0].Action != control.CONNECTED {
				t.Fatalf("emitted %+v, want one CONNECTED event", emitted)
			}
			if emitted[0].Tier != tt.want {
				t.Errorf("CONNECTED reported tier %q, want %q", emitted[0].Tier, tt.want)
			}
		})
	}
}

// TestUnregisterTierChecksIdentity guards the ABA hazard flowTable.remove documents:
// a tier goroutine can still be unwinding when the peer reconnects and registers a
// replacement, and evicting by peer alone would kill the live one.
func TestUnregisterTierChecksIdentity(t *testing.T) {
	t.Parallel()
	sm, _, _ := newTestManager(t)
	id := testPeer(t)

	stale := sm.RegisterTier(id, negotiate.TierWireGuard, func() {})
	// Registering a replacement retires the predecessor, but the predecessor's own
	// deferred unregister still runs afterwards.
	sm.RegisterTier(id, negotiate.TierWireGuard, func() {})
	sm.UnregisterTier(id, stale)

	if !sm.BeginStream(id, fakeConn{}) {
		t.Fatal("BeginStream refused a stream on a live manager")
	}
	defer sm.EndStream(id)

	sm.mu.Lock()
	_, stillRegistered := sm.tiers[id]
	sm.mu.Unlock()
	if !stillRegistered {
		t.Fatal("a stale unregister evicted the live tier")
	}
}

// TestRegisterTierRetiresPredecessor covers the leak a second negotiation would
// otherwise cause: only one tier can carry a peer's traffic, so the displaced one
// has to be told to release its device and substrate.
func TestRegisterTierRetiresPredecessor(t *testing.T) {
	t.Parallel()
	sm, _, _ := newTestManager(t)
	id := testPeer(t)

	stopped := make(chan struct{})
	sm.RegisterTier(id, negotiate.TierWireGuard, func() { close(stopped) })
	sm.RegisterTier(id, negotiate.TierWireGuard, func() {})

	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("the displaced tier was never retired")
	}
}

// TestRegisterTierWhileClosing covers the window between Shutdown starting and a
// tier's own context noticing: a registration that took then would leave a tier
// nothing ever stops.
func TestRegisterTierWhileClosing(t *testing.T) {
	t.Parallel()
	sm, _, _ := newTestManager(t)
	id := testPeer(t)

	sm.Shutdown()

	stopped := make(chan struct{})
	entry := sm.RegisterTier(id, negotiate.TierWireGuard, func() { close(stopped) })
	if entry != nil {
		t.Error("RegisterTier accepted a tier after shutdown")
	}
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("a tier registered during shutdown was never stopped")
	}
	// A nil entry has to be safe to unregister, since callers defer it on the result.
	sm.UnregisterTier(id, entry)
}

// TestShutdownStopsTiersBeforeWaiting is the deadlock guard for the whole tier. A
// non-libp2p tier's forwarded connections are not libp2p streams, so Shutdown's
// stream resets never release them - only the registered stop does. Waiting first
// would wait forever.
func TestShutdownStopsTiersBeforeWaiting(t *testing.T) {
	t.Parallel()
	sm, _, _ := newTestManager(t)
	id := testPeer(t)

	// A handler that only finishes once its tier is stopped, standing in for a
	// forward blocked on a virtual connection.
	release := make(chan struct{})
	sm.RegisterTier(id, negotiate.TierWireGuard, func() { close(release) })
	if !sm.BeginStream(id, fakeConn{}) {
		t.Fatal("BeginStream refused a stream on a live manager")
	}
	go func() {
		<-release
		sm.EndStream(id)
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		sm.Shutdown()
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Shutdown waited for handlers it never released; tier stops must run before the wait")
	}
}

// TestRemoveStopsTier covers the operator DISCONNECT path, which has the same reach
// problem as shutdown: closing the peer's libp2p connection does not sever a data
// plane that is not made of libp2p streams.
func TestRemoveStopsTier(t *testing.T) {
	t.Parallel()
	sm, net, ev := newTestManager(t)
	id := testPeer(t)

	stopped := make(chan struct{})
	sm.RegisterTier(id, negotiate.TierWireGuard, func() { close(stopped) })
	if !sm.BeginStream(id, fakeConn{}) {
		t.Fatal("BeginStream refused a stream on a live manager")
	}

	sm.Remove(id)

	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Remove left the peer's tier running")
	}
	sm.EndStream(id)

	net.mu.Lock()
	closed := len(net.closed)
	net.mu.Unlock()
	if closed != 1 {
		t.Errorf("ClosePeer called %d times, want 1", closed)
	}

	emitted := ev.decoded(t)
	if len(emitted) != 2 || emitted[1].Action != control.DISCONNECT {
		t.Fatalf("emitted %+v, want CONNECTED then DISCONNECT", emitted)
	}
	// EndStream after Remove must not emit a second DISCONNECT: the session is
	// already gone, and a duplicate would confuse a supervisor tracking peers.
	if got := len(ev.decoded(t)); got != 2 {
		t.Errorf("emitted %d events after EndStream, want 2", got)
	}
}

// TestRemoveWithoutSessionIsNoOp preserves the documented contract that
// disconnecting a peer that is not connected emits nothing.
func TestRemoveWithoutSessionIsNoOp(t *testing.T) {
	t.Parallel()
	sm, net, ev := newTestManager(t)

	sm.Remove(testPeer(t))

	net.mu.Lock()
	closed := len(net.closed)
	net.mu.Unlock()
	if closed != 0 {
		t.Errorf("ClosePeer called %d times for an unconnected peer, want 0", closed)
	}
	if emitted := ev.decoded(t); len(emitted) != 0 {
		t.Errorf("emitted %+v for an unconnected peer, want nothing", emitted)
	}
}
