package tunnel

import (
	"slices"
	"strings"
	"sync"
	"time"

	"mtunnel-libp2p/internal/control"
	"mtunnel-libp2p/internal/negotiate"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// Session tracks one connected peer and the tunnel streams it currently has open.
type Session struct {
	ID        peer.ID
	Conn      network.Conn
	CreatedAt time.Time
	// Tier is the data plane the peer's forwarded connections actually ride, fixed
	// for the session's whole life: it is resolved by the negotiate exchange before
	// any forwarded connection can exist, and there is no mid-session renegotiation.
	Tier negotiate.Tier
	// streams counts the tunnel streams the peer currently has open. A client opens
	// one stream per forwarded connection, all multiplexed over a single libp2p
	// connection, so a peer may have several at once.
	streams int
}

// peerTier is a tier registered for a peer, and the hook that tears it down.
//
// It is keyed separately from Session rather than stored on it because the two have
// different lifetimes: a tier is registered as soon as it comes up, before the peer
// opens its first forwarded connection, and stays registered across the gaps when the
// peer has none open and therefore has no session at all.
type peerTier struct {
	tier negotiate.Tier
	stop func()
}

// Age reports how long the session has existed.
func (s *Session) Age() time.Duration {
	return time.Since(s.CreatedAt)
}

// SessionManager tracks connected peers for the host role, emitting CONNECTED and
// DISCONNECT events through its emitter as peers come and go. It satisfies
// control.Sessions so the control channel can list and disconnect peers.
type SessionManager struct {
	mu       sync.Mutex
	sessions map[peer.ID]*Session
	tiers    map[peer.ID]*peerTier
	network  network.Network
	emitter  *control.Emitter

	// handlers tracks in-flight stream handlers so Shutdown can wait for them.
	handlers sync.WaitGroup
	// closing is set once Shutdown begins; afterwards BeginStream refuses new
	// streams so handlers.Wait cannot race a late handlers.Add.
	closing bool
}

// NewSessionManager returns a SessionManager that emits events through emitter.
func NewSessionManager(network network.Network, emitter *control.Emitter) *SessionManager {
	return &SessionManager{
		sessions: make(map[peer.ID]*Session),
		tiers:    make(map[peer.ID]*peerTier),
		network:  network,
		emitter:  emitter,
	}
}

// RegisterTier records that peer id's forwarded connections now ride tier, and that
// stop retires whatever carries it. It returns a handle to pass to UnregisterTier.
//
// stop is what lets Remove and Shutdown reach a data plane libp2p cannot: resetting
// libp2p streams unblocks the libp2p tier and nothing else.
//
// Registering while shutting down does not take: it stops the new tier instead, so a
// tier that came up in the window between Shutdown starting and its own context
// noticing cannot outlive the manager.
func (sm *SessionManager) RegisterTier(id peer.ID, tier negotiate.Tier, stop func()) *peerTier {
	entry := &peerTier{tier: tier, stop: stop}

	sm.mu.Lock()
	if sm.closing {
		sm.mu.Unlock()
		stop()
		return nil
	}
	displaced := sm.tiers[id]
	sm.tiers[id] = entry
	sm.mu.Unlock()

	// Invoked outside the lock: a tier's teardown unregisters itself, which takes
	// this same mutex.
	if displaced != nil {
		// A peer that negotiated a second tier before its first finished unwinding.
		// Only one can carry its traffic, so retire the predecessor rather than leak
		// its device and substrate.
		displaced.stop()
	}
	return entry
}

// UnregisterTier removes a tier registration made by RegisterTier. It is a no-op for
// a nil entry, so a caller can defer it unconditionally on RegisterTier's result.
//
// Like flowTable.remove it checks identity before evicting: a tier goroutine can
// still be unwinding when the peer reconnects and registers a replacement, and
// keying on the peer alone would evict the live one.
func (sm *SessionManager) UnregisterTier(id peer.ID, entry *peerTier) {
	if entry == nil {
		return
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.tiers[id] == entry {
		delete(sm.tiers, id)
	}
}

// BeginStream registers the start of one tunnel stream from peer id and reports
// whether the caller may serve it. The first stream from a peer creates the
// session and emits a single CONNECTED event; further concurrent streams from the
// same peer only increment the active-stream count. It returns false once the
// manager is shutting down, in which case the caller must not serve the stream and
// must not call EndStream.
//
// Every BeginStream that returns true must be paired with exactly one EndStream.
func (sm *SessionManager) BeginStream(id peer.ID, conn network.Conn) bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.closing {
		return false
	}

	sm.handlers.Add(1)

	if session, ok := sm.sessions[id]; ok {
		session.streams++
		return true
	}

	// A peer with no registered tier is on the libp2p floor: that is the tier whose
	// streams arrive with nothing else set up, so the absence of a registration is
	// itself the answer rather than a missing value.
	tier := negotiate.TierLibp2p
	if entry, ok := sm.tiers[id]; ok {
		tier = entry.tier
	}

	sm.sessions[id] = &Session{
		ID:        id,
		Conn:      conn,
		CreatedAt: time.Now(),
		Tier:      tier,
		streams:   1,
	}

	sm.emitter.Emit(control.Output{
		Action:    control.CONNECTED,
		SessionId: id,
		Addr:      conn.RemoteMultiaddr().String(),
		Tier:      tier,
	})

	return true
}

// EndStream records that one tunnel stream from peer id has finished. The session
// - and its single DISCONNECT event - is removed only when the peer's last active
// stream ends, so one connection closing no longer tears down its siblings. The
// finished stream is closed by its own handler; EndStream never touches other
// streams.
func (sm *SessionManager) EndStream(id peer.ID) {
	sm.mu.Lock()
	if session, ok := sm.sessions[id]; ok {
		session.streams--
		if session.streams <= 0 {
			delete(sm.sessions, id)
			sm.emitter.Emit(control.Output{
				Action:    control.DISCONNECT,
				SessionId: id,
			})
		}
	}
	sm.mu.Unlock()

	sm.handlers.Done()
}

// Remove forcibly disconnects a peer in response to an operator request: it resets
// every active tunnel stream, closes the underlying connection, and emits a single
// DISCONNECT event. Ordinary per-stream completion is handled by EndStream instead.
// Disconnecting a peer with no active session is a no-op, so it never emits a
// spurious event for an already-gone peer.
func (sm *SessionManager) Remove(id peer.ID) {
	sm.mu.Lock()
	if _, ok := sm.sessions[id]; !ok {
		sm.mu.Unlock()
		return
	}

	// Retiring the peer's tier is what severs a data plane that is not made of
	// libp2p streams; the resets below reach the libp2p tier and nothing else.
	entry := sm.tiers[id]
	delete(sm.tiers, id)

	for _, conn := range sm.network.ConnsToPeer(id) {
		for _, s := range conn.GetStreams() {
			s.Reset()
		}
	}
	sm.network.ClosePeer(id)

	delete(sm.sessions, id)
	sm.emitter.Emit(control.Output{
		Action:    control.DISCONNECT,
		SessionId: id,
	})
	sm.mu.Unlock()

	// Invoked outside the lock: a tier's teardown unregisters itself, which takes
	// this same mutex.
	if entry != nil {
		entry.stop()
	}
}

// List returns the IDs of the currently connected peers.
func (sm *SessionManager) List() []peer.ID {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	var ids []peer.ID
	for id := range sm.sessions {
		ids = append(ids, id)
	}

	return ids
}

// ActiveTier names the data plane the host's forwarded connections are currently
// riding, for the periodic diagnostics record. With no session open it reports
// nothing; with peers on different tiers it reports each distinct one once, sorted.
// A host serves whichever tier each client negotiated for itself, so collapsing that
// to a single value would mean picking a winner arbitrarily.
func (sm *SessionManager) ActiveTier() string {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	var tiers []negotiate.Tier
	for _, session := range sm.sessions {
		if !slices.Contains(tiers, session.Tier) {
			tiers = append(tiers, session.Tier)
		}
	}
	slices.Sort(tiers)

	// Rendered only here, at the edge, because the diagnostic record wants one
	// field rather than a list. Everything above this line is still a tier.
	return strings.Join(tiersToStrings(tiers), ",")
}

// Shutdown stops accepting new tunnel streams, forcibly resets every active one,
// and waits for their handlers to finish. It emits no per-session DISCONNECT events
// because the whole tunnel is going away. After Shutdown returns the manager
// permanently refuses further streams.
func (sm *SessionManager) Shutdown() {
	sm.mu.Lock()
	sm.closing = true
	stops := make([]func(), 0, len(sm.tiers))
	for _, entry := range sm.tiers {
		stops = append(stops, entry.stop)
	}
	sm.tiers = make(map[peer.ID]*peerTier)
	for id := range sm.sessions {
		for _, conn := range sm.network.ConnsToPeer(id) {
			for _, s := range conn.GetStreams() {
				s.Reset()
			}
		}
		sm.network.ClosePeer(id)
	}
	sm.sessions = make(map[peer.ID]*Session)
	sm.mu.Unlock()

	// Invoked outside the lock, and before the wait below: these are what unblock
	// handlers on a non-libp2p tier, whose connections the resets above never
	// touched, so waiting first could wait forever. A tier's teardown also
	// unregisters itself, which takes this same mutex.
	for _, stop := range stops {
		stop()
	}

	// Safe from an Add/Wait race: closing is now set under the same lock that
	// BeginStream takes, so no handler can call handlers.Add after this point.
	sm.handlers.Wait()
}
