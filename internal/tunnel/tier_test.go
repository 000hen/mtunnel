package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"mtunnel-libp2p/internal/nat"
	"mtunnel-libp2p/internal/negotiate"
	"mtunnel-libp2p/internal/p2p"
)

// testTiers builds a data plane the way a live process does, with real credentials
// and the real registry.
//
// The tests go through newTiers rather than assembling a tiers value themselves so
// that what they exercise is what the binary runs: the advertised tier list comes
// from the registry, so a tier added to the registry and forgotten in a test's
// expectations is a failure rather than a silent divergence.
func testTiers(t *testing.T, opts Options) tiers {
	t.Helper()

	ts, err := newTiers(opts)
	if err != nil {
		t.Fatalf("build tiers: %v", err)
	}
	return ts
}

// testHello builds one side's opening Hello for the given mode, with wgKey standing
// in for the credential the registry would otherwise generate.
//
// The key is overridden rather than read back because these tests care about which
// key travelled, not which one was generated, and a fixed key is what makes "the
// client saw the host's key" checkable.
func testHello(t *testing.T, wgKey [32]byte, mode p2p.TunnelMode, probe bool) negotiate.Hello {
	t.Helper()

	opts := Options{P2P: p2p.Config{TunnelMode: mode, Diagnostic: probe}}
	hello := testTiers(t, opts).hello(opts)
	hello.WireGuardPubKey = wgKey
	return hello
}

// connPair returns the two ends of a loopback TCP connection, closed automatically
// when the test finishes. A real socket, not net.Pipe: the Hello swap is symmetric
// (both sides send before either receives), which needs a buffered substrate - the
// same reason internal/negotiate's own tests use loopback TCP.
func connPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	type accepted struct {
		conn net.Conn
		err  error
	}
	accept := make(chan accepted, 1)
	go func() {
		conn, err := listener.Accept()
		accept <- accepted{conn, err}
	}()

	dialed, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	got := <-accept
	if got.err != nil {
		_ = dialed.Close()
		t.Fatalf("accept: %v", got.err)
	}

	t.Cleanup(func() {
		_ = dialed.Close()
		_ = got.conn.Close()
	})
	return dialed, got.conn
}

// TestExchangeHelloTimesOutOnSilentPeer is the regression test for a peer that
// accepts the negotiate stream and then never replies. Before the per-phase
// deadline this inherited the run context, which is only cancelled at shutdown, so
// the client hung before it ever opened its local listener and the host pinned a
// handler goroutine for the life of the process.
func TestExchangeHelloTimesOutOnSilentPeer(t *testing.T) {
	t.Parallel()
	conn, peer := connPair(t)

	// Read and discard the local Hello so the write completes, then stay silent.
	go func() { _, _ = io.Copy(io.Discard, peer) }()

	start := time.Now()
	_, _, err := exchangeHello(context.Background(), negotiate.NewExchange(conn), testHello(t, [32]byte{}, p2p.TunnelAuto, false), 50*time.Millisecond)
	elapsed := time.Since(start)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("exchangeHello error = %v, want context.DeadlineExceeded", err)
	}
	// The deadline must be what returns, not some unrelated slow path.
	if elapsed > 5*time.Second {
		t.Fatalf("exchangeHello took %v to honour a 50ms deadline", elapsed)
	}
}

func TestProbeAgreed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		local bool
		peer  bool
		want  bool
	}{
		{name: "both asked", local: true, peer: true, want: true},
		// A peer predating PunchProbe decodes as false, which lands here: the newer
		// side must skip the extra phase the older side will never send.
		{name: "peer did not ask", local: true, peer: false, want: false},
		{name: "local did not ask", local: false, peer: true, want: false},
		{name: "neither asked", local: false, peer: false, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := probeAgreed(testHello(t, [32]byte{}, p2p.TunnelAuto, tt.local), testHello(t, [32]byte{}, p2p.TunnelAuto, tt.peer))
			if got != tt.want {
				t.Errorf("probeAgreed(local=%v, peer=%v) = %v, want %v", tt.local, tt.peer, got, tt.want)
			}
		})
	}
}

func TestPunchInfoConversionRoundTrip(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   nat.Credentials
	}{
		{
			name: "complete credentials",
			in: nat.Credentials{
				Ufrag:      "ufrag",
				Pwd:        "password",
				Candidates: []string{"candidate:1 1 udp 2130706431 192.0.2.1 40000 typ host", "candidate:2 1 udp 1694498815 198.51.100.1 40001 typ srflx"},
			},
		},
		// What a side whose own gathering failed sends, so the peer learns to give up
		// rather than waiting out its timeout.
		{name: "empty credentials", in: nat.Credentials{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := fromPunchInfo(toPunchInfo(tt.in, [32]byte{}))
			if !reflect.DeepEqual(got, tt.in) {
				t.Fatalf("round trip returned %+v, want %+v", got, tt.in)
			}
		})
	}
}

// fakePunchAgent stands in for nat.Agent so the probe's phases can be driven without
// sockets. Each side of a probe gets its own instance.
type fakePunchAgent struct {
	local      nat.Credentials
	addRemote  error
	connectErr error
	// conn is what Connect hands back when set. The probe tests do not care what they
	// get, but the cascade tests need both sides to land on the two ends of one real
	// socket pair - the substrate every rung above the punch shares.
	conn net.Conn

	mu       sync.Mutex
	remote   nat.Credentials
	attempts int
	closed   int
}

func (f *fakePunchAgent) Local() nat.Credentials { return f.local }

func (f *fakePunchAgent) AddRemote(remote nat.Credentials) error {
	if f.addRemote != nil {
		return f.addRemote
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.remote = remote
	return nil
}

func (f *fakePunchAgent) Connect(context.Context, bool) (net.Conn, error) {
	f.mu.Lock()
	f.attempts++
	f.mu.Unlock()
	if f.connectErr != nil {
		return nil, f.connectErr
	}
	if f.conn != nil {
		return f.conn, nil
	}
	// net.Pipe is fine here: the probe only ever closes what Connect returns.
	conn, peer := net.Pipe()
	_ = peer.Close()
	return conn, nil
}

func (f *fakePunchAgent) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed++
	return nil
}

func (f *fakePunchAgent) state() (remote nat.Credentials, attempts, closed int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.remote, f.attempts, f.closed
}

func gatheredCredentials(tag string) nat.Credentials {
	return nat.Credentials{
		Ufrag:      tag + "-ufrag",
		Pwd:        tag + "-password",
		Candidates: []string{"candidate:1 1 udp 2130706431 192.0.2.1 40000 typ host"},
	}
}

// probeDeadline bounds how long both halves of a probe may take. With fake agents
// the only real work is a gob swap over loopback TCP, so anything beyond this is a
// stall rather than slowness.
//
// It MUST stay well below punchExchangeTimeout. The failure these tests exist to
// catch is one side returning before it sends its PunchInfo, which strands the peer
// in ExchangePunchInfo for exactly punchExchangeTimeout - so a bound at or above
// that value would let the stranding complete and pass unnoticed, which is precisely
// what an earlier version of this helper did.
const probeDeadline = punchExchangeTimeout / 4

// runProbePair drives both halves of a punch probe against each other over a real
// loopback stream, returning once both have finished. It fails the test if either
// side stalls, and separately asserts the pair finished promptly - the two are not
// redundant, since a stall shorter than the wait bound would otherwise be invisible.
func runProbePair(t *testing.T, clientAgent, hostAgent punchAgent, clientErr, hostErr error) {
	t.Helper()
	clientConn, hostConn := connPair(t)
	opts := Options{PunchTimeout: time.Second}

	factory := func(agent punchAgent, err error) punchFactory {
		return func(context.Context, nat.Config) (punchAgent, error) {
			if err != nil {
				return nil, err
			}
			return agent, nil
		}
	}

	done := make(chan string, 2)
	go func() {
		runPunchProbe(context.Background(), negotiate.NewExchange(clientConn), opts, true, "peer-host", factory(clientAgent, clientErr))
		done <- "client"
	}()
	go func() {
		runPunchProbe(context.Background(), negotiate.NewExchange(hostConn), opts, false, "peer-client", factory(hostAgent, hostErr))
		done <- "host"
	}()

	start := time.Now()
	finished := make([]string, 0, 2)
	for range 2 {
		select {
		case side := <-done:
			finished = append(finished, side)
		case <-time.After(probeDeadline):
			t.Fatalf("punch probe stalled: only %v finished within %v; the two sides are out of lockstep", finished, probeDeadline)
		}
	}
	if elapsed := time.Since(start); elapsed >= probeDeadline {
		t.Fatalf("punch probe pair took %v, want well under %v", elapsed, probeDeadline)
	}
}

// scriptedAgents is a punchFactory that issues one agent per attempt and drives each
// one's outcome from a script.
//
// A factory rather than a single reusable double on purpose: nat.Agent is documented as
// not reusable - its ICE credentials belong to one attempt - so a retry that handed the
// old agent back would be testing something the production path cannot do. Every agent
// it issues is recorded, which is what lets a test assert both how many attempts ran and
// that each got its own agent.
type scriptedAgents struct {
	tag string
	// fail[n] fails the (n+1)th attempt's connectivity checks. Attempts past the end of
	// the script succeed.
	fail []bool

	mu     sync.Mutex
	issued []*fakePunchAgent
}

func (s *scriptedAgents) factory() punchFactory {
	return func(context.Context, nat.Config) (punchAgent, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		agent := &fakePunchAgent{local: gatheredCredentials(s.tag)}
		if n := len(s.issued); n < len(s.fail) && s.fail[n] {
			agent.connectErr = errors.New("checks timed out")
		}
		s.issued = append(s.issued, agent)
		return agent, nil
	}
}

func (s *scriptedAgents) made() []*fakePunchAgent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.issued)
}

// runPunchPair drives both halves of punch against each other over a real loopback
// stream with the given agreed attempt count, and returns each side's error.
//
// Both sides are given the same count deliberately: production derives it from
// negotiate.EffectivePunchAttempts, which is symmetric by construction, and a test that
// passed different numbers would be exercising a state the wire cannot produce.
func runPunchPair(t *testing.T, attempts uint8, client, host *scriptedAgents) (clientErr, hostErr error) {
	t.Helper()
	clientConn, hostConn := connPair(t)
	opts := Options{PunchTimeout: time.Second}

	type outcome struct {
		side   string
		result punchResult
		err    error
	}
	done := make(chan outcome, 2)
	run := func(side string, conn net.Conn, controlling bool, agents *scriptedAgents) {
		result, err := punch(context.Background(), negotiate.NewExchange(conn), opts, controlling, "peer-"+side, [32]byte{}, attempts, agents.factory())
		done <- outcome{side: side, result: result, err: err}
	}
	go run("client", clientConn, true, client)
	go run("host", hostConn, false, host)

	// The bound is per pair, not per attempt, and stays under punchExchangeTimeout for
	// the reason probeDeadline documents: a side that returns without sending strands
	// its peer for the full exchange timeout, and a looser bound would let that pass.
	seen := make([]string, 0, 2)
	for range 2 {
		select {
		case got := <-done:
			seen = append(seen, got.side)
			// Whatever the verdict, a punch that returns must not leave a substrate
			// behind for a caller that was handed an error.
			if got.err != nil && got.result.agent != nil {
				t.Errorf("%s returned an error and an agent; the agent should have been released", got.side)
			}
			if got.result.agent != nil {
				t.Cleanup(func() { _ = got.result.agent.Close() })
			}
			if got.side == "client" {
				clientErr = got.err
			} else {
				hostErr = got.err
			}
		case <-time.After(probeDeadline):
			t.Fatalf("punch stalled: only %v finished within %v; the two sides are out of lockstep", seen, probeDeadline)
		}
	}
	return clientErr, hostErr
}

// TestPunchRetriesInLockstep is the retry's central claim: the two sides make the same
// number of attempts and stop on the same one, whichever of them actually failed.
//
// The asymmetric rows are the point. Each side runs its own ICE agent against its own
// NAT, so "did the punch work" has two answers, and a side that acted on its own answer
// alone would go on to send an Attempt while its peer looped back to gather - two
// message types crossing on one stream, which is a hang rather than a fallback.
func TestPunchRetriesInLockstep(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		attempts    uint8
		clientFails []bool
		hostFails   []bool
		wantErr     bool
		wantAgents  int
	}{
		{
			name:       "both land on the first attempt",
			attempts:   2,
			wantErr:    false,
			wantAgents: 1,
		},
		{
			// The recovery the retry exists for: a first attempt that failed for a
			// reason a second one does not hit.
			name:        "client fails once then lands",
			attempts:    2,
			clientFails: []bool{true},
			wantErr:     false,
			wantAgents:  2,
		},
		{
			// The host is the one that failed, but the client retries too - and had to
			// throw away a substrate that worked, because a substrate the peer does not
			// share is not one.
			name:       "host fails once then lands",
			attempts:   2,
			hostFails:  []bool{true},
			wantErr:    false,
			wantAgents: 2,
		},
		{
			// Exhaustion is the floor, and it is bounded: exactly the agreed number of
			// attempts, not one more.
			name:        "both fail every attempt",
			attempts:    2,
			clientFails: []bool{true, true},
			hostFails:   []bool{true, true},
			wantErr:     true,
			wantAgents:  2,
		},
		{
			// One attempt is wire-identical to a peer predating the field: no outcome
			// swap at all. The asymmetry is not repaired - it cannot be, with nothing
			// exchanged - but neither side may hang on it.
			name:        "a single agreed attempt does not retry",
			attempts:    1,
			clientFails: []bool{true},
			wantErr:     false, // only the host lands; asserted per-side below
			wantAgents:  1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := &scriptedAgents{tag: "client", fail: tt.clientFails}
			host := &scriptedAgents{tag: "host", fail: tt.hostFails}
			clientErr, hostErr := runPunchPair(t, tt.attempts, client, host)

			clientAgents, hostAgents := client.made(), host.made()
			if len(clientAgents) != tt.wantAgents || len(hostAgents) != tt.wantAgents {
				t.Errorf("agents issued = client %d / host %d, want %d each", len(clientAgents), len(hostAgents), tt.wantAgents)
			}

			if tt.attempts == 1 {
				// Without the swap each side reports only what it saw itself, which is
				// exactly the behaviour this pairing is meant to preserve.
				if clientErr == nil {
					t.Error("client punch succeeded, want the failure its own agent reported")
				}
				if hostErr != nil {
					t.Errorf("host punch = %v, want success", hostErr)
				}
				return
			}

			// With the swap in play the verdict is joint, so the two sides must agree.
			if (clientErr != nil) != (hostErr != nil) {
				t.Errorf("sides disagree: client = %v, host = %v", clientErr, hostErr)
			}
			if (clientErr != nil) != tt.wantErr {
				t.Errorf("punch error = %v, want error: %v", clientErr, tt.wantErr)
			}

			// Every agent but the surviving one must be closed. That includes agents
			// whose own Connect succeeded: keeping one would leak an ICE agent and, worse,
			// tempt a caller into using a substrate the peer abandoned.
			assertSpentAgentsClosed(t, "client", clientAgents, clientErr == nil)
			assertSpentAgentsClosed(t, "host", hostAgents, hostErr == nil)
		})
	}
}

// assertSpentAgentsClosed checks that every agent from a superseded attempt was released.
// When the punch succeeded the final agent is the live one and must NOT be closed - it
// owns the substrate every rung above is about to run on.
func assertSpentAgentsClosed(t *testing.T, side string, agents []*fakePunchAgent, succeeded bool) {
	t.Helper()
	for i, agent := range agents {
		_, _, closed := agent.state()
		last := i == len(agents)-1
		if last && succeeded {
			if closed != 0 {
				t.Errorf("%s agent %d closed %d times, want 0 - it owns the surviving substrate", side, i, closed)
			}
			continue
		}
		if closed == 0 {
			t.Errorf("%s agent %d was never closed; a superseded punch attempt leaks its ICE agent", side, i)
		}
	}
}

// TestPunchProbeExchangesAndConnects is the happy path: both sides gather, swap
// credentials over the negotiate stream, and attempt connectivity checks.
func TestPunchProbeExchangesAndConnects(t *testing.T) {
	t.Parallel()
	client := &fakePunchAgent{local: gatheredCredentials("client")}
	host := &fakePunchAgent{local: gatheredCredentials("host")}

	runProbePair(t, client, host, nil, nil)

	clientRemote, clientAttempts, clientClosed := client.state()
	hostRemote, hostAttempts, hostClosed := host.state()

	if !reflect.DeepEqual(clientRemote, host.local) {
		t.Errorf("client received %+v, want the host's credentials %+v", clientRemote, host.local)
	}
	if !reflect.DeepEqual(hostRemote, client.local) {
		t.Errorf("host received %+v, want the client's credentials %+v", hostRemote, client.local)
	}
	if clientAttempts != 1 || hostAttempts != 1 {
		t.Errorf("connect attempts = client %d / host %d, want 1 each", clientAttempts, hostAttempts)
	}
	// The probe is measurement-only: it must release the agent, not leak it into the
	// session it was measuring.
	if clientClosed != 1 || hostClosed != 1 {
		t.Errorf("agent closes = client %d / host %d, want 1 each", clientClosed, hostClosed)
	}
}

// TestPunchProbeSurvivesPeerFailures pins the lockstep property that makes the probe
// safe to run on a live session: whatever goes wrong on one side, both sides still
// send exactly one PunchInfo and both return. A side that bailed out before sending
// would strand its peer in a blocking read for the whole exchange timeout.
func TestPunchProbeSurvivesPeerFailures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name              string
		clientErr         error
		hostAgent         *fakePunchAgent
		wantHostAttempts  int
		wantHostAddRemote bool
	}{
		{
			// The client never gathered, so it sends empty credentials. The host must
			// recognise them as unusable and skip checks rather than attempt them.
			name:             "client gather fails",
			clientErr:        errors.New("gather failed"),
			hostAgent:        &fakePunchAgent{local: gatheredCredentials("host")},
			wantHostAttempts: 0,
		},
		{
			// The host rejects what the client sent; the client's own half is unaffected.
			name:             "host rejects remote candidates",
			hostAgent:        &fakePunchAgent{local: gatheredCredentials("host"), addRemote: nat.ErrNoRemote},
			wantHostAttempts: 0,
		},
		{
			name:              "host connectivity checks fail",
			hostAgent:         &fakePunchAgent{local: gatheredCredentials("host"), connectErr: errors.New("checks timed out")},
			wantHostAttempts:  1,
			wantHostAddRemote: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			client := &fakePunchAgent{local: gatheredCredentials("client")}

			runProbePair(t, client, tt.hostAgent, tt.clientErr, nil)

			remote, attempts, closed := tt.hostAgent.state()
			if attempts != tt.wantHostAttempts {
				t.Errorf("host connect attempts = %d, want %d", attempts, tt.wantHostAttempts)
			}
			if tt.wantHostAddRemote && !reflect.DeepEqual(remote, client.local) {
				t.Errorf("host received %+v, want the client's credentials %+v", remote, client.local)
			}
			if closed != 1 {
				t.Errorf("host agent closes = %d, want 1", closed)
			}
		})
	}
}

// TestPunchProbeSurvivesBrokenFactory covers a factory returning neither an agent
// nor an error. That is a test-double bug rather than a runtime condition, but it
// runs inside a libp2p stream handler, where a nil dereference would take down more
// than the probe - so it must degrade to a gather failure and still keep lockstep.
func TestPunchProbeSurvivesBrokenFactory(t *testing.T) {
	t.Parallel()
	host := &fakePunchAgent{local: gatheredCredentials("host")}

	clientConn, hostConn := connPair(t)
	opts := Options{PunchTimeout: time.Second}

	done := make(chan struct{}, 2)
	go func() {
		runPunchProbe(context.Background(), negotiate.NewExchange(clientConn), opts, true, "peer-host",
			func(context.Context, nat.Config) (punchAgent, error) { return nil, nil })
		done <- struct{}{}
	}()
	go func() {
		runPunchProbe(context.Background(), negotiate.NewExchange(hostConn), opts, false, "peer-client",
			func(context.Context, nat.Config) (punchAgent, error) { return host, nil })
		done <- struct{}{}
	}()

	for range 2 {
		select {
		case <-done:
		case <-time.After(probeDeadline):
			t.Fatal("a broken factory stalled the probe instead of degrading to gather-failed")
		}
	}

	// The broken side must still have sent its empty PunchInfo, so the peer sees
	// unusable credentials rather than blocking.
	if _, attempts, _ := host.state(); attempts != 0 {
		t.Errorf("host connect attempts = %d, want 0", attempts)
	}
}

// TestHandlerGroupRefusesAfterShutdown pins the property that makes the host's
// negotiate handler safe to wait on: once shutdown has begun, begin must refuse, so
// a handler goroutine libp2p dispatched just before the handler was removed cannot
// call Add concurrently with Wait.
func TestHandlerGroupRefusesAfterShutdown(t *testing.T) {
	t.Parallel()
	var g handlerGroup

	if !g.begin() {
		t.Fatal("begin returned false before shutdown")
	}

	waited := make(chan struct{})
	go func() {
		g.shutdown()
		close(waited)
	}()

	// shutdown must not return while the in-flight handler is outstanding.
	select {
	case <-waited:
		t.Fatal("shutdown returned while a handler was still in flight")
	case <-time.After(50 * time.Millisecond):
	}

	g.done()
	select {
	case <-waited:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not return after the last handler finished")
	}

	if g.begin() {
		t.Error("begin returned true after shutdown; a late handler could race Wait")
	}
}

// TestExchangeHelloResolvesTier covers the success path through the same helper, so
// the added deadline is not silently breaking a healthy exchange, and pins the
// property the whole cascade rests on: both sides see the same pair of Hellos and so
// reach the same tier with no extra round trip. A disagreement here would strand one
// side waiting for a phase the other never sends.
func TestExchangeHelloResolvesTier(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		clientMode p2p.TunnelMode
		hostMode   p2p.TunnelMode
		want       negotiate.Tier
	}{
		// The default on both sides. WireGuard winning here is what makes the tier
		// default-preferred rather than opt-in.
		{name: "auto both sides", clientMode: p2p.TunnelAuto, hostMode: p2p.TunnelAuto, want: negotiate.TierWireGuard},
		{name: "forced wireguard both sides", clientMode: p2p.TunnelWireGuard, hostMode: p2p.TunnelWireGuard, want: negotiate.TierWireGuard},
		{name: "host pinned to the floor", clientMode: p2p.TunnelAuto, hostMode: p2p.TunnelLibp2p, want: negotiate.TierLibp2p},
		{name: "client pinned to the floor", clientMode: p2p.TunnelLibp2p, hostMode: p2p.TunnelAuto, want: negotiate.TierLibp2p},
		// Incompatible forcing converges on the floor rather than failing to agree;
		// what forcing changes is each side's response to that, not the selection.
		{name: "incompatible forcing", clientMode: p2p.TunnelWireGuard, hostMode: p2p.TunnelLibp2p, want: negotiate.TierLibp2p},
	}

	hostKey := [32]byte{0xAB, 31: 0xCD}
	type outcome struct {
		tier negotiate.Tier
		peer negotiate.Hello
		err  error
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			clientConn, hostConn := connPair(t)

			run := func(conn net.Conn, local negotiate.Hello) <-chan outcome {
				out := make(chan outcome, 1)
				go func() {
					tier, peer, err := exchangeHello(context.Background(), negotiate.NewExchange(conn), local, 5*time.Second)
					out <- outcome{tier, peer, err}
				}()
				return out
			}

			// Start both sides before awaiting either: neither completes until its
			// counterpart has sent.
			clientOut := run(clientConn, testHello(t, [32]byte{}, tt.clientMode, false))
			hostOut := run(hostConn, testHello(t, hostKey, tt.hostMode, false))
			client := <-clientOut
			host := <-hostOut

			if client.err != nil || host.err != nil {
				t.Fatalf("exchangeHello errors: client=%v host=%v", client.err, host.err)
			}
			if client.tier != tt.want || host.tier != tt.want {
				t.Fatalf("resolved tiers = client %q / host %q, want %q on both", client.tier, host.tier, tt.want)
			}
			if client.peer.WireGuardPubKey != hostKey {
				t.Errorf("client saw host key %x, want %x", client.peer.WireGuardPubKey, hostKey)
			}
			if host.peer.WireGuardPubKey != [32]byte{} {
				t.Errorf("host saw client key %x, want the zero key", host.peer.WireGuardPubKey)
			}
		})
	}
}

// TestSupportedTiers pins what each tunnel mode advertises. The expectations name
// every tier this build implements, so registering a rung without deciding how the
// modes should treat it fails here rather than shipping unadvertised.
func TestSupportedTiers(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		mode p2p.TunnelMode
		want []negotiate.Tier
	}{
		{name: "auto", mode: p2p.TunnelAuto, want: []negotiate.Tier{negotiate.TierWireGuard, negotiate.TierQUIC, negotiate.TierLibp2p}},
		// Forcing narrows the list to {forced tier, floor}. The floor stays present
		// even so, which keeps tier selection a plain intersection with no special
		// cases; forcing takes effect in how each side reacts to a tier that does not
		// come up, not by making the intersection empty.
		{name: "wireguard forced", mode: p2p.TunnelWireGuard, want: []negotiate.Tier{negotiate.TierWireGuard, negotiate.TierLibp2p}},
		{name: "quic forced", mode: p2p.TunnelQUIC, want: []negotiate.Tier{negotiate.TierQUIC, negotiate.TierLibp2p}},
		{name: "libp2p forced", mode: p2p.TunnelLibp2p, want: []negotiate.Tier{negotiate.TierLibp2p}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := testTiers(t, Options{}).supported(tt.mode)
			if !slices.Equal(got, tt.want) {
				t.Errorf("supported(%q) = %v, want %v", tt.mode, got, tt.want)
			}
			// The floor must be last and present whatever the mode: a peer that
			// supports nothing else still has to resolve to a working tunnel.
			if got[len(got)-1] != negotiate.TierLibp2p {
				t.Errorf("supported(%q) = %v, want the libp2p floor last", tt.mode, got)
			}
		})
	}
}
