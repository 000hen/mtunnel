package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	"mtunnel-libp2p/internal/nat"
	"mtunnel-libp2p/internal/negotiate"
	"mtunnel-libp2p/internal/transport"

	"github.com/libp2p/go-libp2p/core/peer"
)

// These tests drive the real fallback ladder - the real WireGuard device, the real
// QUIC handshake, the real substrate hand-off between them - with only the punch
// itself replaced. That is the one part that needs a NAT to be interesting, and the
// part whose result is a plain net.Conn, so a loopback socket pair substitutes for it
// exactly.
//
// What they exist to catch is the class of bug that only appears on the second rung:
// the first tier's teardown leaving the shared substrate unusable. Nothing in a
// single-tier test can see that, and in production it would present as "the cascade
// ran and every fallback failed" - which reads like bad luck rather than a defect.

const (
	// cascadeHandshakeTimeout is how long a rung gets to prove itself. A refused rung
	// costs exactly this, and a working one lands in single-digit milliseconds over
	// loopback, so it is sized for the slowest plausible machine rather than tuned.
	cascadeHandshakeTimeout = time.Second

	// cascadeDeadline bounds the whole exchange, generously: it is a stall detector,
	// not a performance assertion.
	cascadeDeadline = 30 * time.Second
)

// udpLink connects an unconnected UDP socket to one fixed peer, which is the shape
// nat.Agent's punched conn has: ICE nominated a single candidate pair, so there is
// exactly one address to read from and write to.
type udpLink struct {
	*net.UDPConn
	remote *net.UDPAddr
}

func (u udpLink) Read(p []byte) (int, error) {
	n, _, err := u.UDPConn.ReadFromUDP(p)
	return n, err
}

func (u udpLink) Write(p []byte) (int, error) { return u.UDPConn.WriteToUDP(p, u.remote) }
func (u udpLink) RemoteAddr() net.Addr        { return u.remote }

// substrateShape selects what the rungs of a ladder run actually sit on.
type substrateShape int

const (
	// punchedSubstrate is production's shape. nat.Agent.Connect never hands a rung the
	// socket it punched: it hands over nat.WithDeadlines(conn), because pion/ice
	// implements the deadline setters as stubs that record nothing. That wrapper is the
	// thing the hand-off between rungs actually depends on, so it is the default here.
	punchedSubstrate substrateShape = iota

	// rawSubstrate is the bare loopback socket, whose deadlines the kernel implements.
	// It is the control, kept so a break in deadlineConn stays distinguishable from a
	// break in a rung: both shapes failing means a rung is at fault, only the punched
	// one failing means the wrapper is.
	rawSubstrate

	// stubDeadlineSubstrate accepts a read deadline and does nothing with it, which is
	// what pion/ice's Conn does and the reason nat.WithDeadlines exists at all.
	//
	// It is fault injection, not a shape production ships: a rung tearing down on one of
	// these cannot release its read loop, so it waits out the close grace and closes the
	// substrate to break out. Any teardown that outlasts the grace ends the same way -
	// a device too busy to come back, say - but this is the one trigger that fires
	// deterministically, which is what a test needs.
	stubDeadlineSubstrate
)

// stubDeadlineConn accepts deadlines and ignores them, exactly as pion/ice's Conn does.
type stubDeadlineConn struct{ net.Conn }

func (stubDeadlineConn) SetDeadline(time.Time) error      { return nil }
func (stubDeadlineConn) SetReadDeadline(time.Time) error  { return nil }
func (stubDeadlineConn) SetWriteDeadline(time.Time) error { return nil }

// substratePair returns the two ends of a loopback UDP link, standing in for what a
// punch produces. A real datagram socket rather than net.Pipe because both tiers above
// the punch are datagram protocols and a message boundary is not a detail either of
// them can do without.
//
// What the socket's own read deadlines are is deliberately *not* what the ladder runs
// on. The kernel implements them and they simply work, so a hand-off tested against
// one is tested against an implementation that cannot exhibit the failure mode the
// test exists for - which is how finding 001 shipped green. Under punchedSubstrate
// each end is wrapped exactly as Agent.Connect wraps a punched conn, so the deadline
// implementation under test is the one the shipped binary runs on.
func substratePair(t *testing.T, shape substrateShape) (net.Conn, net.Conn) {
	t.Helper()

	listen := func() *net.UDPConn {
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatalf("listen udp: %v", err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}

	a, b := listen(), listen()
	var one, two net.Conn = udpLink{a, b.LocalAddr().(*net.UDPAddr)}, udpLink{b, a.LocalAddr().(*net.UDPAddr)}
	switch shape {
	case punchedSubstrate:
		// No extra cleanup: each wrapper's pump is parked in its socket's Read, and the
		// close registered above is what releases it - the same event that releases it
		// in production, where Agent.Close closes the sockets underneath.
		one, two = nat.WithDeadlines(one), nat.WithDeadlines(two)
	case stubDeadlineSubstrate:
		one, two = stubDeadlineConn{one}, stubDeadlineConn{two}
	}
	return one, two
}

// fixedAgent is a punch factory that hands out one already-connected substrate.
func fixedAgent(substrate net.Conn, tag string) punchFactory {
	return func(context.Context, nat.Config) (punchAgent, error) {
		return &fakePunchAgent{local: gatheredCredentials(tag), conn: substrate}, nil
	}
}

// cascadeHostResult is what the host half of a ladder run ended on.
type cascadeHostResult struct {
	// rung is the tier the host stood up, if one got that far.
	rung hostRung
	// floor records the client giving up on every rung and naming the libp2p floor.
	floor bool
	// requested is every rung the client asked for, in order, the libp2p floor included.
	requested []negotiate.Tier
	err       error
}

// serveCascadeCounterpart is the host half of the ladder.
//
// It is written out here rather than reused from serveUpperTiers because that
// function is bound to a libp2p network.Stream and a SessionManager, neither of which
// this test needs to make its point. The message sequence is the same one
// serveUpperTiers implements, and every tier-building call is the production one.
//
// refuse names the rungs it acknowledges and then does not stand up. That is not a
// contrived failure: it is exactly what a host whose standUpRung returned an error
// does, and it signals nothing back, because the client is running the same rung on
// the same substrate and finds out for itself.
func serveCascadeCounterpart(ctx context.Context, x *negotiate.Exchange, opts Options, ids tierIdentities, peerHello negotiate.Hello, substrate net.Conn, t transport.Transport, refuse ...negotiate.Tier) cascadeHostResult {
	var res cascadeHostResult

	// next records what the client asked for before returning it. The record is the only
	// way a test tells "the client tried the next rung and it failed" apart from "the
	// client stopped asking" - both end at the floor, and only one of them is what a
	// dead substrate should produce.
	next := func() (negotiate.Attempt, error) {
		attempt, err := receiveRungRequest(ctx, x)
		if err == nil {
			res.requested = append(res.requested, attempt.Tier)
		}
		return attempt, err
	}

	attempts := negotiate.EffectivePunchAttempts(punchAttemptsFor(opts), peerHello.PunchAttempts)
	punched, err := punch(ctx, x, opts, false, "cascade-client", ids.quic.Fingerprint, attempts, fixedAgent(substrate, "host"))
	if err != nil {
		res.err = fmt.Errorf("host punch: %w", err)
		return res
	}

	deps := hostTierDeps{transport: t}
	pending, err := next()
	for err == nil {
		if pending.Tier == negotiate.TierLibp2p {
			res.floor = true
			return res
		}
		if err = sendRungAck(ctx, x, pending.Tier); err != nil {
			break
		}
		if slices.Contains(refuse, pending.Tier) {
			pending, err = next()
			continue
		}
		rung, outcome, standErr := standUpRung(ctx, pending.Tier, punched, opts, ids, peerHello, deps)
		if standErr != nil {
			res.err = fmt.Errorf("stand up %s (%s): %w", pending.Tier, outcome, standErr)
			return res
		}
		res.rung = rung
		return res
	}
	res.err = err
	return res
}

// cascadeRun is one full two-sided ladder run over a shared substrate.
type cascadeRun struct {
	client tierResult
	host   cascadeHostResult
	err    error
}

// runCascade wires a client and a host onto one negotiate stream and one substrate
// pair, and runs the ladder to whatever it settles on. Both halves run concurrently
// because they have to: the acknowledgement each rung waits for comes from the other
// side, and the QUIC rung's Accept does not return until the client dials it.
func runCascade(t *testing.T, shape substrateShape, network string, refuse ...negotiate.Tier) cascadeRun {
	t.Helper()

	clientIDs, err := newTierIdentities()
	if err != nil {
		t.Fatalf("client identities: %v", err)
	}
	hostIDs, err := newTierIdentities()
	if err != nil {
		t.Fatalf("host identities: %v", err)
	}

	forwarder, err := transportFor(network, false)
	if err != nil {
		t.Fatalf("transport for %q: %v", network, err)
	}

	clientSignal, hostSignal := connPair(t)
	clientSub, hostSub := substratePair(t, shape)

	opts := Options{HandshakeTimeout: cascadeHandshakeTimeout}
	cascade := []negotiate.Tier{negotiate.TierWireGuard, negotiate.TierQUIC, negotiate.TierLibp2p}
	clientHello := negotiate.Hello{SupportedTiers: cascade, WireGuardPubKey: clientIDs.wg.public}
	hostHello := negotiate.Hello{SupportedTiers: cascade, WireGuardPubKey: hostIDs.wg.public}

	ctx, cancel := context.WithTimeout(context.Background(), cascadeDeadline)
	defer cancel()

	served := make(chan cascadeHostResult, 1)
	go func() {
		served <- serveCascadeCounterpart(ctx, negotiate.NewExchange(hostSignal), opts, hostIDs, clientHello, hostSub, forwarder, refuse...)
	}()

	result, clientErr := climbCascade(
		ctx,
		negotiate.NewExchange(clientSignal),
		opts,
		clientIDs,
		hostHello,
		peer.ID("cascade-host"),
		forwarder.Network(),
		cascade,
		fixedAgent(clientSub, "client"),
	)

	var host cascadeHostResult
	select {
	case host = <-served:
	case <-ctx.Done():
		t.Fatal("host half of the cascade never finished")
	}

	if clientErr == nil {
		t.Cleanup(func() { _ = result.close() })
	}
	if host.rung.close != nil {
		t.Cleanup(func() { _ = host.rung.close() })
	}
	return cascadeRun{client: result, host: host, err: clientErr}
}

// TestCascadeFallsBackFromWireGuardToQUIC is the test M4 exists for. The client tries
// WireGuard, gets nothing back, tears it down, and brings QUIC up on the very same
// punched conn - and the tunnel then carries bytes, which is a stronger claim than
// "the handshake completed".
//
// It is also the regression test for a substrate handed on in an unusable state. The
// WireGuard bind releases its receive loop with a read deadline in the past; if it
// does not clear that deadline on the way out, every QUIC read here fails instantly
// and the second rung can never come up.
//
// The two rows are the same ladder over the two substrate shapes - see substrateShape.
// Only the punched row proves anything about production; the raw row is what tells you
// whether a failure came from deadlineConn or from a rung.
func TestCascadeFallsBackFromWireGuardToQUIC(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		shape substrateShape
	}{
		{"punched", punchedSubstrate},
		{"raw", rawSubstrate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			run := runCascade(t, tc.shape, "tcp", negotiate.TierWireGuard)
			if run.err != nil {
				t.Fatalf("climbCascade: %v (host: %+v)", run.err, run.host)
			}
			if run.host.err != nil {
				t.Fatalf("host half: %v", run.host.err)
			}
			if run.client.tier != negotiate.TierQUIC {
				t.Fatalf("client settled on tier %q, want %q", run.client.tier, negotiate.TierQUIC)
			}
			if run.host.rung.tier != negotiate.TierQUIC {
				t.Fatalf("host stood up tier %q, want %q", run.host.rung.tier, negotiate.TierQUIC)
			}

			ctx, cancel := context.WithTimeout(context.Background(), cascadeDeadline)
			defer cancel()
			echoThrough(t, ctx, run.client.opener, run.host.rung.accept)
		})
	}
}

// TestCascadeExhaustsEveryRung covers the other end of the ladder: with no rung able
// to come up, the client has to give up and tell the host so, rather than hang or
// leave the host serving a tier nobody is on. The host's libp2p data handler is
// already live, so naming the floor is the whole handover.
func TestCascadeExhaustsEveryRung(t *testing.T) {
	t.Parallel()

	run := runCascade(t, punchedSubstrate, "tcp", negotiate.TierWireGuard, negotiate.TierQUIC)
	if run.err == nil {
		t.Fatalf("climbCascade unexpectedly succeeded on tier %q", run.client.tier)
	}
	if run.host.err != nil {
		t.Fatalf("host half: %v", run.host.err)
	}
	if !run.host.floor {
		t.Error("host was never told the client had fallen to the libp2p floor")
	}
	// Every rung, in order, and only then the floor. This is the baseline the abandoned
	// substrate case below is measured against - both end on the floor, and what tells
	// them apart is how much of the ladder the client got through first.
	want := []negotiate.Tier{negotiate.TierWireGuard, negotiate.TierQUIC, negotiate.TierLibp2p}
	if !slices.Equal(run.host.requested, want) {
		t.Errorf("client requested %v, want %v", run.host.requested, want)
	}
}

// TestCascadeStopsWhenTheSubstrateIsAbandoned covers the failure that made a recoverable
// WireGuard problem an unrecoverable session: a rung whose teardown cannot release its
// read loop closes the shared substrate to break out, and everything below it then fails
// for a reason that has nothing to do with that tier.
//
// The client must notice and stop. Continuing costs a wasted handshake timeout and, worse,
// produces a report naming QUIC as broken when QUIC was never given a substrate to run on
// - which is exactly how this has been presenting in the field.
//
// The substrate here accepts read deadlines and ignores them; see stubDeadlineSubstrate
// for why that stands in for every way a teardown outlasts the close grace.
func TestCascadeStopsWhenTheSubstrateIsAbandoned(t *testing.T) {
	t.Parallel()

	run := runCascade(t, stubDeadlineSubstrate, "tcp", negotiate.TierWireGuard)
	if run.err == nil {
		t.Fatalf("climbCascade unexpectedly succeeded on tier %q", run.client.tier)
	}
	if !substrateAbandoned(run.err) {
		t.Errorf("climbCascade error = %v, want one reporting an abandoned substrate", run.err)
	}
	if run.host.err != nil {
		t.Fatalf("host half: %v", run.host.err)
	}

	// The whole point: WireGuard, then straight to the floor. A QUIC request in here
	// means the client tried a rung on a conn that was already closed.
	want := []negotiate.Tier{negotiate.TierWireGuard, negotiate.TierLibp2p}
	if !slices.Equal(run.host.requested, want) {
		t.Errorf("client requested %v, want %v - it kept climbing on a dead substrate", run.host.requested, want)
	}
	if !run.host.floor {
		t.Error("host was never told the client had fallen to the libp2p floor")
	}
}

// TestCascadeCarriesForwardedUDP runs the same fallback with a UDP-forwarded service,
// which selects each tier's datagram sub-mode. It is a separate test rather than a
// table row because the sub-mode swap reaches all the way down: a QUIC stream becomes
// a QUIC datagram carrying flowmux frames, and only an end-to-end round trip shows
// that the substitution held together.
func TestCascadeCarriesForwardedUDP(t *testing.T) {
	t.Parallel()

	run := runCascade(t, punchedSubstrate, "udp", negotiate.TierWireGuard)
	if run.err != nil {
		t.Fatalf("climbCascade: %v (host: %+v)", run.err, run.host)
	}
	if run.host.err != nil {
		t.Fatalf("host half: %v", run.host.err)
	}
	if run.client.tier != negotiate.TierQUIC {
		t.Fatalf("client settled on tier %q, want %q", run.client.tier, negotiate.TierQUIC)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cascadeDeadline)
	defer cancel()
	echoThrough(t, ctx, run.client.opener, run.host.rung.accept)
}

// echoThrough opens one forwarded connection over the winning tier and bounces a
// payload off the host end of it, which is the only evidence that the tier is
// actually carrying traffic rather than merely built.
func echoThrough(t *testing.T, ctx context.Context, opener transport.Opener, acceptor streamAcceptor) {
	t.Helper()

	const payload = "cascade round trip"

	echoed := make(chan error, 1)
	go func() {
		echoed <- func() error {
			s, err := acceptor.AcceptStream(ctx)
			if err != nil {
				return fmt.Errorf("accept: %w", err)
			}
			defer s.Close()

			buf := make([]byte, len(payload))
			if _, err := io.ReadFull(s, buf); err != nil {
				return fmt.Errorf("read: %w", err)
			}
			if _, err := s.Write(buf); err != nil {
				return fmt.Errorf("write back: %w", err)
			}
			return nil
		}()
	}()

	stream, err := opener.OpenStream(ctx)
	if err != nil {
		t.Fatalf("open forwarded connection: %v", err)
	}
	defer stream.Close()

	if _, err := stream.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(stream, got); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != payload {
		t.Errorf("round trip returned %q, want %q", got, payload)
	}

	select {
	case err := <-echoed:
		if err != nil && !errors.Is(err, io.EOF) {
			t.Errorf("host end of the forwarded connection: %v", err)
		}
	case <-ctx.Done():
		t.Error("host end of the forwarded connection never finished")
	}
}
