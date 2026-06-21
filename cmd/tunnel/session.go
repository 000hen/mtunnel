package main

import (
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

type Session struct {
	ID        peer.ID
	Conn      network.Conn
	CreatedAt time.Time
	// streams counts the tunnel streams the peer currently has open. A client
	// opens one stream per forwarded connection, all multiplexed over a single
	// libp2p connection, so a peer may have several at once.
	streams int
}

type SessionManager struct {
	mu       sync.Mutex
	Sessions map[peer.ID]*Session
	Network  network.Network

	// handlers tracks in-flight stream handlers so Shutdown can wait for them.
	handlers sync.WaitGroup
	// closing is set once Shutdown begins; afterwards BeginStream refuses new
	// streams so handlers.Wait cannot race a late handlers.Add.
	closing bool
}

func NewSessionManager(network network.Network) *SessionManager {
	return &SessionManager{
		Sessions: make(map[peer.ID]*Session),
		Network:  network,
	}
}

// BeginStream registers the start of one tunnel stream from peer id and reports
// whether the caller may serve it. The first stream from a peer creates the
// session and emits a single CONNECTED event; further concurrent streams from
// the same peer only increment the active-stream count. It returns false once
// the manager is shutting down, in which case the caller must not serve the
// stream and must not call EndStream.
//
// Every BeginStream that returns true must be paired with exactly one EndStream.
func (sm *SessionManager) BeginStream(id peer.ID, conn network.Conn) bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.closing {
		return false
	}

	sm.handlers.Add(1)

	if session, ok := sm.Sessions[id]; ok {
		session.streams++
		return true
	}

	sm.Sessions[id] = &Session{
		ID:        id,
		Conn:      conn,
		CreatedAt: time.Now(),
		streams:   1,
	}

	sendOutputAction(OutputAction{
		Action:    CONNECTED,
		SessionId: id,
		Addr:      conn.RemoteMultiaddr().String(),
	})

	return true
}

// EndStream records that one tunnel stream from peer id has finished. The
// session - and its single DISCONNECT event - is removed only when the peer's
// last active stream ends, so one connection closing no longer tears down its
// siblings. The finished stream is closed by its own handler; EndStream never
// touches other streams.
func (sm *SessionManager) EndStream(id peer.ID) {
	sm.mu.Lock()
	if session, ok := sm.Sessions[id]; ok {
		session.streams--
		if session.streams <= 0 {
			delete(sm.Sessions, id)
			sendOutputAction(OutputAction{
				Action:    DISCONNECT,
				SessionId: id,
			})
		}
	}
	sm.mu.Unlock()

	sm.handlers.Done()
}

// RemoveSession forcibly disconnects a peer in response to an operator request:
// it resets every active tunnel stream, closes the underlying connection, and
// emits a single DISCONNECT event. Ordinary per-stream completion is handled by
// EndStream instead. Disconnecting a peer with no active session is a no-op, so
// it never emits a spurious event for an already-gone peer.
func (sm *SessionManager) RemoveSession(id peer.ID) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if _, ok := sm.Sessions[id]; !ok {
		return
	}

	for _, conn := range sm.Network.ConnsToPeer(id) {
		for _, s := range conn.GetStreams() {
			s.Reset()
		}
	}
	sm.Network.ClosePeer(id)

	delete(sm.Sessions, id)
	sendOutputAction(OutputAction{
		Action:    DISCONNECT,
		SessionId: id,
	})
}

func (sm *SessionManager) ListSessions() []peer.ID {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	var sessionIDs []peer.ID
	for id := range sm.Sessions {
		sessionIDs = append(sessionIDs, id)
	}

	return sessionIDs
}

// Shutdown stops accepting new tunnel streams, forcibly resets every active one,
// and waits for their handlers to finish. It emits no per-session DISCONNECT
// events because the whole tunnel is going away. After Shutdown returns the
// manager permanently refuses further streams.
func (sm *SessionManager) Shutdown() {
	sm.mu.Lock()
	sm.closing = true
	for id := range sm.Sessions {
		for _, conn := range sm.Network.ConnsToPeer(id) {
			for _, s := range conn.GetStreams() {
				s.Reset()
			}
		}
		sm.Network.ClosePeer(id)
	}
	sm.Sessions = make(map[peer.ID]*Session)
	sm.mu.Unlock()

	// Safe from an Add/Wait race: closing is now set under the same lock that
	// BeginStream takes, so no handler can call handlers.Add after this point.
	sm.handlers.Wait()
}

func (s *Session) Age() time.Duration {
	return time.Since(s.CreatedAt)
}
