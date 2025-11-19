package main

import (
	"context"
	"errors"
	"log"
	"sync"

	"github.com/google/uuid"
	"github.com/quic-go/quic-go"
)

type Session struct {
	ID   string
	conn *quic.Conn
	mu   sync.Mutex
}

type SessionManager struct {
	sessions map[string]*Session
	mu       sync.Mutex
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*Session),
	}
}

func (sm *SessionManager) AddSession(conn *quic.Conn) *Session {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	id := uuid.New().String()
	session := &Session{
		ID:   id,
		conn: conn,
	}
	sm.sessions[id] = session

	return session
}

func (sm *SessionManager) GetSession(id string) (*Session, bool) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, exists := sm.sessions[id]
	return session, exists
}

func (sm *SessionManager) RemoveSession(id string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	delete(sm.sessions, id)
}

func (sm *SessionManager) ListSessions() []string {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	ids := make([]string, 0, len(sm.sessions))
	for id := range sm.sessions {
		ids = append(ids, id)
	}

	return ids
}

func (sm *SessionManager) CloseAllSessions() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	for id, session := range sm.sessions {
		session.conn.CloseWithError(0, "server shutting down")
		delete(sm.sessions, id)
	}
}

func (sm *SessionManager) ForceCloseSession(id string) error {
	sm.mu.Lock()
	session, exists := sm.sessions[id]
	sm.mu.Unlock()

	if !exists {
		return nil
	}

	return session.Close()
}

func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.conn.CloseWithError(0, "session closed")
}

func (s *Session) GetConn() *quic.Conn {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.conn
}

func (s *Session) HandleSession(sm *SessionManager, network string, port int, handler func(*quic.Stream, string, int)) {
	defer func() {
		log.Printf("Session %s from %s terminated", s.ID, s.conn.RemoteAddr())
		sm.RemoveSession(s.ID)
	}()

	go func() {
		<-s.conn.Context().Done()
		cause := context.Cause(s.conn.Context())
		log.Printf("Session context done for %s: %v", s.conn.RemoteAddr(), cause)
	}()

	for {
		ctx := context.Background()
		stream, err := s.conn.AcceptStream(ctx)
		if err != nil {
			var appErr *quic.ApplicationError
			var idleErr *quic.IdleTimeoutError
			var transportErr *quic.TransportError

			switch {
			case errors.As(err, &appErr):
				log.Printf("  Client closed gracefully (code %d): %s", appErr.ErrorCode, appErr.ErrorMessage)
			case errors.As(err, &idleErr):
				log.Println("  Client idle timeout - no activity")
			case errors.As(err, &transportErr):
				log.Printf("  Transport error (code %d): %s", transportErr.ErrorCode, transportErr.ErrorMessage)
			default:
				log.Printf("  Stream accept error: %v", err)
			}

			return
		}

		go handler(stream, network, port)
	}
}
