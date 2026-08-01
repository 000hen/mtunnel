package tunnel

import "sync"

// handlerGroup tracks in-flight stream handlers so shutdown can wait for them, and
// refuses new ones once shutdown has begun.
//
// A bare sync.WaitGroup cannot do this job from a libp2p stream handler: shutdown
// removes the handler and then waits, but libp2p may already have dispatched a
// handler goroutine that has not yet reached its Add - and an Add concurrent with
// Wait is exactly the race sync.WaitGroup forbids. Setting closing under the same
// mutex that begin takes closes that window: after shutdown returns from the lock,
// no further Add can happen.
//
// This is the same invariant SessionManager maintains for data streams via its
// closing flag; handlerGroup is the stripped-down version for stream handlers that
// have no session and emit no events, which is what the negotiate handler is.
type handlerGroup struct {
	mu      sync.Mutex
	closing bool
	wg      sync.WaitGroup
}

// begin registers one in-flight handler and reports whether the caller may proceed.
// It returns false once shutdown has begun, in which case the caller must not serve
// the stream and must not call done.
//
// Every begin that returns true must be paired with exactly one done.
func (g *handlerGroup) begin() bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.closing {
		return false
	}
	g.wg.Add(1)
	return true
}

// done records that one handler has finished.
func (g *handlerGroup) done() { g.wg.Done() }

// shutdown stops accepting new handlers and waits for the in-flight ones to return.
// It does not cancel them: callers are expected to have cancelled the context those
// handlers run under first, so this waits for an abort already in progress rather
// than for the handlers' full natural duration.
func (g *handlerGroup) shutdown() {
	g.mu.Lock()
	g.closing = true
	g.mu.Unlock()

	g.wg.Wait()
}
