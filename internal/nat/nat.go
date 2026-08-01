// Package nat performs an independent NAT hole punch with ICE, producing a direct
// net.Conn between two peers that no longer involves libp2p in the data path.
//
// It is a leaf package in the same sense as internal/transport: it imports the
// standard library and pion/ice, never libp2p. libp2p's own DCUtR punch has no API
// for handing out the socket it produced, so a tunnel tier that wants to own a
// socket has to punch one for itself. The only thing libp2p contributes is a
// channel to swap Credentials over, which the caller supplies - this package never
// sees it.
//
// The API is deliberately split into gather (New), exchange (the caller's job), and
// connect (Connect), because the caller must carry this side's Credentials to the
// peer and bring back the peer's before connectivity checks can start.
package nat

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/stun/v3"
)

// DefaultSTUNServers are the public STUN servers used when a caller configures
// none. Two independent operators, so one being unreachable still leaves a
// server-reflexive candidate obtainable.
var DefaultSTUNServers = []string{
	"stun:stun.l.google.com:19302",
	"stun:stun1.l.google.com:19302",
	"stun:stun.cloudflare.com:3478",
}

// DefaultTimeout bounds each punch phase separately - gathering, then connectivity
// checks - rather than the punch as a whole. Gathering normally finishes well
// inside a second; it is the checks against an uncooperative NAT that use the
// budget. A caller wanting a hard ceiling on both should pass a context with a
// deadline.
const DefaultTimeout = 8 * time.Second

// ErrNoRemote reports that Connect was called before the peer's Credentials were
// supplied, which can never succeed: without remote candidates there is nothing to
// run connectivity checks against.
var ErrNoRemote = errors.New("nat: remote credentials not set")

// Credentials is everything a peer needs to run ICE connectivity checks against
// this side. It is transport-agnostic on purpose: the caller decides how to carry
// it (this project sends it over a libp2p stream as negotiate.PunchInfo).
type Credentials struct {
	Ufrag      string
	Pwd        string
	Candidates []string // ice.Candidate.Marshal() form, one per entry
}

// Valid reports whether c is complete enough to attempt a punch against. An
// incomplete value is not an error to send - a peer whose own gathering failed
// still has to send something so both sides stay in lockstep - it just means the
// receiver should skip the attempt.
func (c Credentials) Valid() bool {
	return c.Ufrag != "" && c.Pwd != "" && len(c.Candidates) > 0
}

// Config selects the servers and budget for a punch. The zero value is usable:
// it means the default STUN servers and DefaultTimeout.
type Config struct {
	// STUNServers are stun: URLs. A nil slice means DefaultSTUNServers; an empty
	// non-nil slice means no STUN at all, leaving host candidates only. Entries that
	// fail to parse are skipped with a warning rather than failing the punch, so one
	// bad CLI entry cannot disable NAT traversal outright.
	STUNServers []string

	// Timeout bounds each phase. Zero means DefaultTimeout.
	Timeout time.Duration

	// Diagnostic gates the tunnel_nat_* slog records, matching the flag of the same
	// name elsewhere in the binary.
	Diagnostic bool

	// includeLoopback adds 127.0.0.1 host candidates. Only tests set it: pion filters
	// loopback by default because a real punch between two machines can never select
	// a loopback pair, but two agents inside one test process can.
	includeLoopback bool
}

func (c Config) withDefaults() Config {
	if c.STUNServers == nil {
		c.STUNServers = DefaultSTUNServers
	}
	if c.Timeout <= 0 {
		c.Timeout = DefaultTimeout
	}
	return c
}

// An Agent is one side of a single punch attempt. It is not reusable: ICE
// credentials are per-attempt, so a failed punch needs a fresh Agent.
//
// Close tears down the agent and any net.Conn Connect returned - the conn is a view
// onto the agent's sockets, not an independently owned resource.
type Agent struct {
	agent *ice.Agent
	cfg   Config

	local      Credentials
	localTypes []string

	remote      Credentials
	remoteTypes []string
	hasRemote   bool

	closeOnce sync.Once
	closeErr  error
}

// New creates an ICE agent and gathers this side's candidates, blocking until
// gathering completes, ctx is done, or the configured timeout expires. On a partial
// gather it returns the candidates it did get rather than failing: host candidates
// alone are enough for a punch between peers on the same network, and a
// server-reflexive candidate the peer cannot use is no worse than none.
func New(ctx context.Context, cfg Config) (*Agent, error) {
	cfg = cfg.withDefaults()

	iceAgent, err := ice.NewAgent(&ice.AgentConfig{
		Urls:         parseSTUNServers(cfg.STUNServers, cfg.Diagnostic),
		NetworkTypes: []ice.NetworkType{ice.NetworkTypeUDP4, ice.NetworkTypeUDP6},
		// Host and server-reflexive only: relay candidates would need a TURN server,
		// which this project deliberately does not depend on - libp2p's circuit relay
		// is already the fallback when a punch fails.
		CandidateTypes:    []ice.CandidateType{ice.CandidateTypeHost, ice.CandidateTypeServerReflexive},
		STUNGatherTimeout: &cfg.Timeout,
		IncludeLoopback:   cfg.includeLoopback,
		LoggerFactory:     logFactory{diagnostic: cfg.Diagnostic},
	})
	if err != nil {
		return nil, fmt.Errorf("create ICE agent: %w", err)
	}

	agent := &Agent{agent: iceAgent, cfg: cfg}
	if err := agent.gather(ctx); err != nil {
		_ = iceAgent.Close()
		return nil, err
	}
	return agent, nil
}

// gather runs trickle gathering to completion and records the result as this side's
// Credentials. Candidates are collected in one shot rather than trickled to the
// peer because they travel in a single negotiate message.
func (a *Agent) gather(ctx context.Context) error {
	var (
		mu    sync.Mutex
		cands []ice.Candidate
	)
	done := make(chan struct{})
	var closeDone sync.Once

	// A nil candidate is pion's end-of-gathering signal (Agent.setGatheringState
	// enqueues one on reaching GatheringStateComplete), not a candidate to record.
	if err := a.agent.OnCandidate(func(c ice.Candidate) {
		if c == nil {
			closeDone.Do(func() { close(done) })
			return
		}
		mu.Lock()
		cands = append(cands, c)
		mu.Unlock()
	}); err != nil {
		return fmt.Errorf("register ICE candidate handler: %w", err)
	}

	if err := a.agent.GatherCandidates(); err != nil {
		return fmt.Errorf("gather ICE candidates: %w", err)
	}

	gatherCtx, cancel := context.WithTimeout(ctx, a.cfg.Timeout)
	defer cancel()

	var partial bool
	select {
	case <-done:
	case <-gatherCtx.Done():
		partial = true
	}

	// The handler may still be appending after a partial gather; take a snapshot
	// under the lock and stop reading the slice afterwards.
	mu.Lock()
	marshalled := make([]string, len(cands))
	types := make([]string, len(cands))
	for i, c := range cands {
		marshalled[i] = c.Marshal()
		types[i] = c.Type().String()
	}
	mu.Unlock()

	if len(marshalled) == 0 {
		if partial {
			return fmt.Errorf("gather ICE candidates: %w", gatherCtx.Err())
		}
		return errors.New("nat: no ICE candidates gathered")
	}

	ufrag, pwd, err := a.agent.GetLocalUserCredentials()
	if err != nil {
		return fmt.Errorf("read local ICE credentials: %w", err)
	}

	a.local = Credentials{Ufrag: ufrag, Pwd: pwd, Candidates: marshalled}
	a.localTypes = types

	if a.cfg.Diagnostic {
		slog.Info("tunnel_nat_gather",
			"outcome", map[bool]string{true: "partial", false: "complete"}[partial],
			"candidates", len(marshalled),
			"candidate_types", types,
		)
	}
	return nil
}

// Local returns this side's Credentials, ready to send to the peer.
func (a *Agent) Local() Credentials {
	return a.local
}

// MaxRemoteCandidates caps how many of a peer's candidates are parsed. A real
// gatherer produces a handful - one per local interface per network type, plus a
// server-reflexive candidate per STUN server - so anything approaching this bound is
// already pathological, and ICE checks every remaining candidate against every local
// one anyway.
//
// The cap bounds the parsing and connectivity-check work a peer can induce. It does
// not bound the decode that produced the slice, which is the caller's concern: this
// package is handed an already-decoded value and has no view of the wire.
const MaxRemoteCandidates = 64

// AddRemote registers the peer's Credentials. A candidate that fails to parse is
// skipped rather than fatal, so a peer gathering a candidate type this build does
// not understand degrades to the candidates it does. It reports an error only when
// nothing usable survives, since Connect would then be guaranteed to fail.
//
// Candidates beyond MaxRemoteCandidates are ignored.
func (a *Agent) AddRemote(remote Credentials) error {
	if remote.Ufrag == "" || remote.Pwd == "" {
		return fmt.Errorf("%w: peer sent no ICE credentials", ErrNoRemote)
	}

	candidates := remote.Candidates
	if len(candidates) > MaxRemoteCandidates {
		a.warn(fmt.Sprintf("peer sent %d ICE candidates, using the first %d", len(candidates), MaxRemoteCandidates), nil)
		candidates = candidates[:MaxRemoteCandidates]
	}

	types := make([]string, 0, len(candidates))
	for _, raw := range candidates {
		candidate, err := ice.UnmarshalCandidate(raw)
		if err != nil {
			a.warn("skipping unparseable remote ICE candidate", err)
			continue
		}
		if err := a.agent.AddRemoteCandidate(candidate); err != nil {
			a.warn("skipping rejected remote ICE candidate", err)
			continue
		}
		types = append(types, candidate.Type().String())
	}
	if len(types) == 0 {
		return fmt.Errorf("%w: no usable remote ICE candidates", ErrNoRemote)
	}

	a.remote = remote
	a.remoteTypes = types
	a.hasRemote = true
	return nil
}

// Connect runs ICE connectivity checks and returns the punched conn. controlling
// selects the ICE role: exactly one side must be controlling, and this project maps
// that onto the client, which is always the side that initiates.
//
// It blocks until a candidate pair is nominated, ctx is done, or the configured
// timeout expires, and emits the tunnel_nat_punch record either way.
//
// The returned conn honours read and write deadlines, which ice.Conn itself does not
// - see deadlineConn. Every consumer of a punched substrate depends on that, so the
// wrapping happens here rather than at each call site.
func (a *Agent) Connect(ctx context.Context, controlling bool) (net.Conn, error) {
	if !a.hasRemote {
		return nil, ErrNoRemote
	}

	connectCtx, cancel := context.WithTimeout(ctx, a.cfg.Timeout)
	defer cancel()

	role, connect := "controlled", a.agent.Accept
	if controlling {
		role, connect = "controlling", a.agent.Dial
	}

	start := time.Now()
	conn, err := connect(connectCtx, a.remote.Ufrag, a.remote.Pwd)
	if err != nil {
		a.logPunch(role, "failed", time.Since(start), err)
		return nil, fmt.Errorf("ICE connect as %s: %w", role, err)
	}
	a.logPunch(role, "connected", time.Since(start), nil)
	return withDeadlines(conn), nil
}

// Close releases the agent and everything derived from it, including a conn a
// successful Connect handed back. It is safe to call more than once.
func (a *Agent) Close() error {
	a.closeOnce.Do(func() { a.closeErr = a.agent.Close() })
	return a.closeErr
}

// logPunch emits the tunnel_nat_punch record. The selected pair is only available
// on success and is read best-effort: a diagnostic record must never be the reason
// a punch outcome changes.
func (a *Agent) logPunch(role, outcome string, elapsed time.Duration, cause error) {
	if !a.cfg.Diagnostic {
		return
	}
	attrs := []any{
		"outcome", outcome,
		"role", role,
		"duration_ms", elapsed.Milliseconds(),
		"local_candidate_types", a.localTypes,
		"remote_candidate_types", a.remoteTypes,
	}
	if pair, err := a.agent.GetSelectedCandidatePair(); err == nil && pair != nil {
		attrs = append(attrs,
			"selected_local_type", pair.Local.Type().String(),
			"selected_remote_type", pair.Remote.Type().String(),
			"selected_pair", pair.String(),
		)
	}
	if cause != nil {
		attrs = append(attrs, "error", cause.Error())
	}
	slog.Info("tunnel_nat_punch", attrs...)
}

// warn records a non-fatal problem with a single candidate. cause may be nil, for
// the cases where the message is the whole story and there is no underlying error to
// attach - dereferencing it unconditionally would turn a diagnostic into a panic.
func (a *Agent) warn(msg string, cause error) {
	if !a.cfg.Diagnostic {
		return
	}
	attrs := []any{"message", msg}
	if cause != nil {
		attrs = append(attrs, "error", cause.Error())
	}
	slog.Warn("tunnel_nat_candidate", attrs...)
}

// parseSTUNServers converts configured URLs into pion's form, dropping entries it
// cannot parse. Returning a shorter list is the right failure mode here: gathering
// still yields host candidates, and losing every server-reflexive candidate is what
// the punch outcome record is there to report.
func parseSTUNServers(servers []string, diagnostic bool) []*stun.URI {
	uris := make([]*stun.URI, 0, len(servers))
	for _, raw := range servers {
		uri, err := stun.ParseURI(raw)
		if err != nil {
			if diagnostic {
				slog.Warn("tunnel_nat_stun_server", "server", raw, "error", err.Error())
			}
			continue
		}
		uris = append(uris, uri)
	}
	return uris
}
