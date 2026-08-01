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

// substratePair returns the two ends of a loopback UDP link, standing in for what a
// punch produces. A real datagram socket rather than net.Pipe for two reasons: both
// tiers above the punch are datagram protocols, and a real socket honours read
// deadlines - which is what makes the substrate hand-off between rungs observable
// here at all.
func substratePair(t *testing.T) (net.Conn, net.Conn) {
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
	return udpLink{a, b.LocalAddr().(*net.UDPAddr)}, udpLink{b, a.LocalAddr().(*net.UDPAddr)}
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
	err   error
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
	punched, err := punch(ctx, x, opts, false, "cascade-client", ids.quic.Fingerprint, fixedAgent(substrate, "host"))
	if err != nil {
		return cascadeHostResult{err: fmt.Errorf("host punch: %w", err)}
	}

	deps := hostTierDeps{transport: t}
	pending, err := receiveRungRequest(ctx, x)
	for err == nil {
		if pending.Tier == negotiate.TierLibp2p {
			return cascadeHostResult{floor: true}
		}
		if err = sendRungAck(ctx, x, pending.Tier); err != nil {
			break
		}
		if slices.Contains(refuse, pending.Tier) {
			pending, err = receiveRungRequest(ctx, x)
			continue
		}
		rung, outcome, standErr := standUpRung(ctx, pending.Tier, punched, opts, ids, peerHello, deps)
		if standErr != nil {
			return cascadeHostResult{err: fmt.Errorf("stand up %s (%s): %w", pending.Tier, outcome, standErr)}
		}
		return cascadeHostResult{rung: rung}
	}
	return cascadeHostResult{err: err}
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
func runCascade(t *testing.T, network string, refuse ...negotiate.Tier) cascadeRun {
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
	clientSub, hostSub := substratePair(t)

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
func TestCascadeFallsBackFromWireGuardToQUIC(t *testing.T) {
	t.Parallel()

	run := runCascade(t, "tcp", negotiate.TierWireGuard)
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
}

// TestCascadeExhaustsEveryRung covers the other end of the ladder: with no rung able
// to come up, the client has to give up and tell the host so, rather than hang or
// leave the host serving a tier nobody is on. The host's libp2p data handler is
// already live, so naming the floor is the whole handover.
func TestCascadeExhaustsEveryRung(t *testing.T) {
	t.Parallel()

	run := runCascade(t, "tcp", negotiate.TierWireGuard, negotiate.TierQUIC)
	if run.err == nil {
		t.Fatalf("climbCascade unexpectedly succeeded on tier %q", run.client.tier)
	}
	if run.host.err != nil {
		t.Fatalf("host half: %v", run.host.err)
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

	run := runCascade(t, "udp", negotiate.TierWireGuard)
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
