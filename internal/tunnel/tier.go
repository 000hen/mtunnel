package tunnel

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"sync"
	"time"

	"mtunnel-libp2p/internal/nat"
	"mtunnel-libp2p/internal/negotiate"
	"mtunnel-libp2p/internal/p2p"
	"mtunnel-libp2p/internal/tier"
	"mtunnel-libp2p/internal/transport"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// tiers is this process's data plane: the registry of rungs it can build, and the
// ephemeral credentials they were built with.
//
// The two travel together because every phase needs both - the credentials are what
// goes on the wire (the WireGuard public key in Hello, the certificate fingerprint
// in PunchInfo) and the registry is what turns the agreed name back into something
// that carries traffic - and separating them only produces two parameters that must
// never disagree.
type tiers struct {
	set *tier.Set
	ids tier.Identities
}

// newTiers generates this run's tier credentials and builds the registry over them.
//
// Everything it generates is ephemeral, matching the libp2p peer identity: a restart
// is a new identity on every axis. All of it is generated whatever the tunnel mode,
// because the mode decides which tiers this side *offers*, and a peer that withheld
// a credential would force the floor on a session that could have used something
// better.
func newTiers(opts Options) (tiers, error) {
	ids, err := tier.NewIdentities()
	if err != nil {
		return tiers{}, err
	}
	params := tier.Params{
		HandshakeTimeout: opts.HandshakeTimeout,
		Diagnostic:       opts.P2P.Diagnostic,
	}
	return tiers{set: tier.NewSet(ids, params), ids: ids}, nil
}

// supported derives this side's advertised preference order from the tunnel mode.
// The libp2p floor is always last and always present, so a peer that supports
// nothing else still resolves to a working tunnel.
//
// What is advertised is what this build actually implements - the registry, not a
// list restated here - so a tier that exists on the wire but not in this binary is
// never offered. Forcing narrows the list but does not remove the floor, which is
// what keeps tier selection a pure intersection with no special cases. What forcing
// actually changes is the response to failure: see climbCascade (hard failure) and
// RunHost (no libp2p data handler registered at all).
func (t tiers) supported(mode p2p.TunnelMode) []negotiate.Tier {
	if forced, ok := forcedTier(mode); ok {
		if _, ok := t.set.Lookup(forced); ok {
			return []negotiate.Tier{forced, negotiate.TierLibp2p}
		}
		return []negotiate.Tier{negotiate.TierLibp2p}
	}
	if mode == p2p.TunnelLibp2p {
		return []negotiate.Tier{negotiate.TierLibp2p}
	}
	return append(t.set.IDs(), negotiate.TierLibp2p)
}

// hello builds this side's negotiate.Hello.
//
// The punch probe tracks the diagnostic flag because that probe exists only to
// produce diagnostic records - a session that negotiates a tier above the floor
// punches for real instead, and never runs the probe.
func (t tiers) hello(opts Options) negotiate.Hello {
	return negotiate.Hello{
		SupportedTiers:  t.supported(opts.P2P.TunnelMode),
		WireGuardPubKey: t.ids.WireGuardPublicKey(),
		PunchProbe:      opts.P2P.Diagnostic,
		PunchAttempts:   punchAttemptsFor(opts),
	}
}

// session assembles what one negotiated session contributes to a tier: the peer
// material learned over the negotiate stream, plus the network being forwarded.
func tierSession(network transport.Network, peerHello negotiate.Hello, punched punchResult) tier.Session {
	return tier.Session{
		Network:             network,
		PeerWireGuardKey:    peerHello.WireGuardPubKey,
		PeerQUICFingerprint: punched.peerFingerprint,
	}
}

// tierResult is what one peer session's negotiation and fallback ladder produced.
type tierResult struct {
	// selected is the rung that actually came up - not the one negotiation aimed at -
	// and is what the CONNECTED event reports.
	selected negotiate.Tier
	// opener carries forwarded connections when a tier above the floor came up. It is
	// nil on the libp2p floor, where the caller's own streamOpener already does the
	// job.
	opener transport.Opener
	// close tears down whatever the ladder built. Never nil; a no-op on the floor.
	close func() error
}

// libp2pFloor is the result every failed or skipped ladder resolves to: today's
// behaviour, with nothing new to tear down.
func libp2pFloor() tierResult {
	return tierResult{selected: negotiate.TierLibp2p, close: func() error { return nil }}
}

// forcedTier maps a tunnel mode onto the single tier it pins the session to, and
// reports whether it pins one at all.
//
// It is the one place the CLI's vocabulary meets the wire's. The two enums are
// separate on purpose: p2p.TunnelMode also has values that are not tiers ("auto"),
// and a tier can exist without a flag to force it - auto still selects it - so
// adding a rung does not oblige anyone to touch this.
func forcedTier(mode p2p.TunnelMode) (negotiate.Tier, bool) {
	switch mode {
	case p2p.TunnelWireGuard:
		return negotiate.TierWireGuard, true
	case p2p.TunnelQUIC:
		return negotiate.TierQUIC, true
	default:
		return "", false
	}
}

// forcesTier reports whether mode pins the session to one tier above the floor.
//
// Forcing changes nothing about selection - see tiers.supported - only what each
// side does when the forced tier does not come up: the client returns the error
// instead of falling back, and the host leaves the libp2p data handler unregistered
// so a client that fell back anyway finds nothing listening.
func forcesTier(mode p2p.TunnelMode) bool {
	_, ok := forcedTier(mode)
	return ok
}

// punchAttemptsFor resolves this side's advertised attempt count.
//
// It is a function rather than a default applied inline so that the number put in the
// Hello and the number handed to negotiate.EffectivePunchAttempts come from one place.
// If those two ever disagreed the peer would compute a different limit from the same
// exchange, and the retry loop's whole guarantee is that both sides count alike.
func punchAttemptsFor(opts Options) uint8 {
	if opts.PunchAttempts == 0 {
		return DefaultPunchAttempts
	}
	return opts.PunchAttempts
}

// exchangeHello runs the Hello swap under its own deadline, so a peer that opens the
// stream but never replies cannot stall the caller past timeout. Both roles go
// through it; the timeout is a parameter rather than a constant read inline only so
// tests can drive the expiry path in milliseconds.
//
// Cancelling the context is what abandons the swap, not what unblocks the underlying
// read - the caller still has to reset or close the stream afterwards, which both
// roles do on error.
func exchangeHello(ctx context.Context, x *negotiate.Exchange, local negotiate.Hello, timeout time.Duration) (negotiate.Tier, negotiate.Hello, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return x.Negotiate(ctx, local)
}

// negotiateTierClient opens a negotiate stream to target, runs the tier handshake,
// and climbs the fallback cascade to whatever data plane will actually carry traffic.
//
// In auto mode it never fails the session: any error - a peer that predates the
// negotiate protocol, a failed punch, a WireGuard handshake that never lands, a QUIC
// handshake after it - resolves to the libp2p floor, which is exactly the behaviour
// that existed before tier negotiation. Failing hard would turn an optional upgrade
// into a new way for a working tunnel to break. Under a forced -tunnel-mode it does
// the opposite and returns the error, because the whole point of forcing a tier is to
// find out whether it works rather than to be quietly rescued.
//
// tokenWGPubKey is the host key the client already learned from the token; the Hello
// copy is authoritative and a disagreement is only logged. network is the forwarded
// network, which selects each tier's datagram sub-mode.
//
// wg tracks a background punch probe when one runs. The probe only happens on the
// floor - a session with a shared cascade punches for real, in the foreground.
func negotiateTierClient(ctx context.Context, h host.Host, target peer.ID, opts Options, ts tiers, tokenWGPubKey [32]byte, network transport.Network, wg *sync.WaitGroup) (result tierResult, err error) {
	// Named return plus defer, rather than a call on each path out: this function reaches
	// the floor from eight places and the record is worth nothing if it misses one.
	// Every return here carries a tier, including the error paths, which return
	// libp2pFloor alongside the error.
	defer func() { logTierSelected(result.selected) }()

	forced := forcesTier(opts.P2P.TunnelMode)

	stream, err := p2p.OpenNegotiateStream(ctx, h, target, opts.P2P)
	if err != nil {
		if forced {
			return libp2pFloor(), fmt.Errorf("open negotiate stream to %s: %w", target, err)
		}
		log.Printf("Tier negotiation with %s unavailable, using %s tier: %v", target, negotiate.TierLibp2p, err)
		return libp2pFloor(), nil
	}

	local := ts.hello(opts)
	exchange := negotiate.NewExchange(stream)
	selected, peerHello, err := exchangeHello(ctx, exchange, local, negotiateTimeout)
	if err != nil {
		_ = stream.Reset()
		if forced {
			return libp2pFloor(), fmt.Errorf("negotiate tunnel tier with %s: %w", target, err)
		}
		log.Printf("Tier negotiation with %s failed, using %s tier: %v", target, negotiate.TierLibp2p, err)
		return libp2pFloor(), nil
	}
	if tokenWGPubKey != ([32]byte{}) && peerHello.WireGuardPubKey != tokenWGPubKey {
		// Not fatal - the negotiated key wins - but a mismatch means the token was
		// generated by a different host process than the one just reached, which is
		// worth surfacing rather than silently tolerating.
		log.Printf("Host %s advertised a WireGuard key differing from the token's copy; using the negotiated key", target)
	}
	logTierNegotiated(opts.P2P, local, peerHello, selected)

	cascade := negotiate.SharedCascade(local.SupportedTiers, peerHello.SupportedTiers)

	// Both sides compute the same cascade and the same probeAgreed from the same pair
	// of Hellos, so both take the same branch here. That is what keeps the stream in
	// lockstep: the two upper branches each add messages to the exchange, and one side
	// taking a different branch would strand the other.
	switch {
	case cascade[0] != negotiate.TierLibp2p:
		result, err := climbCascade(ctx, exchange, opts, ts, peerHello, target, network, cascade, newPunchAgent)
		if err == nil {
			// The negotiate stream is the tier's lifeline: the host tears its half down
			// when the stream ends, so it stays open as long as the tunnel does.
			result.close = tier.CloseAll(result.close, stream.Close)
			return result, nil
		}
		// Reset rather than close. climbCascade has already told the host it is falling
		// to the floor where it could; where it could not, the exchange is in an unknown
		// state and only a reset reliably releases the host's reader.
		_ = stream.Reset()
		if forced {
			return libp2pFloor(), fmt.Errorf("tunnel mode %s forced but unavailable: %w", opts.P2P.TunnelMode, err)
		}
		log.Printf("No tunnel tier above the floor came up with %s, using %s tier: %v", target, negotiate.TierLibp2p, err)
		return libp2pFloor(), nil

	case probeAgreed(local, peerHello):
		wg.Go(func() {
			defer stream.Close()
			// The client side initiates, so it takes ICE's controlling role.
			runPunchProbe(ctx, exchange, opts, true, target.String(), newPunchAgent)
		})
		return libp2pFloor(), nil

	default:
		_ = stream.Close()
		if forced {
			return libp2pFloor(), fmt.Errorf("tunnel mode %s forced but host %s does not support it", opts.P2P.TunnelMode, target)
		}
		return libp2pFloor(), nil
	}
}

// climbCascade runs Rung A once and then walks the rungs above it, in the order both
// sides agreed, until one comes up or none is left.
//
// One punch serves every rung. WireGuard and QUIC both want nothing more than a
// working net.Conn to the peer, and punching again per rung would triple the cost of
// the slowest phase to re-derive a path that already exists. What makes the sharing
// safe is that a rung's teardown returns the substrate untouched: internal/nat's
// Agent owns it throughout, its deadline wrapper is what lets the previous rung's read
// loop be released without closing it (see nat.deadlineConn), and each rung clears the
// deadline it used to do the releasing. A rung that failed may leave a few of its own
// datagrams already buffered on the substrate; the next one reads them as packets from
// nobody and drops them, which is what both tiers do with any unrecognised datagram.
//
// newAgent is a parameter so tests can drive every transition - punch fails, the first
// rung fails and the second comes up, every rung fails - over a real socket pair with
// no NAT, STUN server, or libp2p host involved.
func climbCascade(ctx context.Context, x *negotiate.Exchange, opts Options, ts tiers, peerHello negotiate.Hello, target peer.ID, network transport.Network, cascade []negotiate.Tier, newAgent punchFactory) (tierResult, error) {
	start := time.Now()
	attempts := negotiate.EffectivePunchAttempts(punchAttemptsFor(opts), peerHello.PunchAttempts)
	punched, err := punch(ctx, x, opts, true, target.String(), ts.ids.QUICFingerprint(), attempts, newAgent)
	if err != nil {
		logTierAttempt(opts, cascade[0], tier.OutcomePunchFailed, time.Since(start), err)
		return tierResult{}, err
	}
	session := tierSession(network, peerHello, punched)

	var lastErr error
	for _, id := range cascade {
		if id == negotiate.TierLibp2p {
			break
		}

		rungStart := time.Now()
		if err := requestRung(ctx, x, id); err != nil {
			// The exchange is the only thing keeping the two sides in step, so a failure
			// here is not a failure of this rung - it means there is no longer a way to
			// agree on the next one either.
			logTierAttempt(opts, id, tier.OutcomeRequestFailed, time.Since(rungStart), err)
			_ = punched.agent.Close()
			return tierResult{}, err
		}

		rung, outcome, err := ts.set.Dial(ctx, id, punched.conn, session)
		if err != nil {
			logTierAttempt(opts, id, outcome, time.Since(rungStart), err)
			lastErr = err
			if outcome == tier.OutcomeSubstrateAbandoned {
				// The rung's teardown closed the conn every remaining rung would have run
				// on, so there is nothing below this to try. Walking on would produce a
				// handshake failure that says nothing about the next tier and a report
				// that names the wrong culprit - which is exactly how this failure has
				// been presenting as "QUIC did not work either".
				break
			}
			continue
		}
		logTierAttempt(opts, id, outcome, time.Since(rungStart), nil)
		return tierResult{
			selected: id,
			opener:   rung.Opener,
			// The agent goes last: it owns the substrate every rung ran on, so releasing
			// it before the rung on top would pull the floor out from under a teardown
			// still in progress.
			close: tier.CloseAll(rung.Close, punched.agent.Close),
		}, nil
	}

	// Every rung failed. Tell the host so it stops standing tiers up and releases the
	// substrate on its side too; the floor needs no acknowledgement, since the libp2p
	// data handler it falls back to is already live.
	fallbackCtx, cancel := context.WithTimeout(ctx, negotiateTimeout)
	_ = x.SendAttempt(fallbackCtx, negotiate.Attempt{Tier: negotiate.TierLibp2p})
	cancel()
	_ = punched.agent.Close()

	if lastErr == nil {
		lastErr = errors.New("no tunnel tier above the floor was attempted")
	}
	return tierResult{}, lastErr
}

// requestRung tells the host which rung is next and waits for it to acknowledge.
//
// The acknowledgement is sequencing, not consent - the host replies before it builds
// anything, and both sides already agree on the cascade. What it buys is the one
// guarantee a one-way message could not give: that the previous rung is fully torn
// down before this one starts. Without it the host's WireGuard bind would still be
// draining datagrams off the shared substrate while the client had already begun a
// QUIC handshake on it, and the Initials it swallowed would cost a full PTO backoff
// to recover - a self-inflicted delay in exactly the path that exists to be fast.
func requestRung(ctx context.Context, x *negotiate.Exchange, id negotiate.Tier) error {
	ctx, cancel := context.WithTimeout(ctx, negotiateTimeout)
	defer cancel()

	if err := x.SendAttempt(ctx, negotiate.Attempt{Tier: id}); err != nil {
		return err
	}
	ack, err := x.ReceiveAttempt(ctx)
	if err != nil {
		return err
	}
	if ack.Tier != id {
		return fmt.Errorf("host acknowledged tier %q for a %q attempt", ack.Tier, id)
	}
	return nil
}

// hostTierDeps is what the host side needs to serve a forwarded connection, whatever
// tier it arrives on. It exists so the negotiate handler's signature does not grow a
// parameter per collaborator.
type hostTierDeps struct {
	tiers     tiers
	session   *SessionManager
	transport transport.Transport
	localAddr string
}

// negotiateTierHost is the host side of the handshake, invoked from the negotiate
// stream handler. It owns the stream's lifetime, and when a tier above the floor is
// in play it keeps that stream open for as long as the tunnel lives - see
// serveUpperTiers.
//
// The host never chooses: it serves whichever rung the client asks for, and the
// client is the side that finds out a rung failed. The libp2p handler registered in
// RunHost stays live alongside an upper tier, so a client that exhausted the cascade
// is already served. The one exception is a forced -tunnel-mode, which leaves that
// handler unregistered so the fallback fails loudly.
func negotiateTierHost(ctx context.Context, opts Options, deps hostTierDeps, s network.Stream) {
	defer s.Close()

	remote := s.Conn().RemotePeer()
	local := deps.tiers.hello(opts)
	exchange := negotiate.NewExchange(s)
	selected, peerHello, err := exchangeHello(ctx, exchange, local, negotiateTimeout)
	if err != nil {
		// Reset rather than close: the peer should see a failed negotiation, not a
		// clean end-of-stream it might mistake for an empty answer.
		_ = s.Reset()
		log.Printf("Tier negotiation with %s failed: %v", remote, err)
		return
	}
	logTierNegotiated(opts.P2P, local, peerHello, selected)

	// Both sides compute the cascade and probeAgreed from the same pair of Hellos, so
	// both take the same branch here. That is what keeps the stream in lockstep: the
	// two upper branches each add messages to the exchange, and one side taking a
	// different branch would strand the other.
	switch {
	case selected != negotiate.TierLibp2p:
		serveUpperTiers(ctx, exchange, opts, peerHello, deps, s)
	case probeAgreed(local, peerHello):
		// The punch probe runs inline rather than in its own goroutine because libp2p
		// already gives every inbound stream a dedicated handler goroutine.
		runPunchProbe(ctx, exchange, opts, false, remote.String(), newPunchAgent)
	}
}

// serveUpperTiers punches once and then serves whatever rung the client asks for,
// re-serving when the client falls back, until the peer goes away.
//
// It blocks for the tunnel's whole lifetime, which is deliberate: the negotiate
// stream is the tier's lifeline, and tying the tunnel to the handler goroutine that
// owns that stream means the peer disconnecting, an operator DISCONNECT, and process
// shutdown all tear down through the same path.
//
// The host acknowledges each request before it builds anything. Standing the rung up
// first would deadlock the tiers that cannot come up alone: quictun.Accept blocks
// until the client dials, and the client does not dial until the acknowledgement
// arrives. Building after the reply is safe because it is far faster than the reply's
// own round trip - a netstack device or a QUIC listener costs microseconds - so the
// host is listening well before the client's first packet is on the wire.
func serveUpperTiers(ctx context.Context, x *negotiate.Exchange, opts Options, peerHello negotiate.Hello, deps hostTierDeps, s network.Stream) {
	remote := s.Conn().RemotePeer()

	start := time.Now()
	attempts := negotiate.EffectivePunchAttempts(punchAttemptsFor(opts), peerHello.PunchAttempts)
	punched, err := punch(ctx, x, opts, false, remote.String(), deps.tiers.ids.QUICFingerprint(), attempts, newPunchAgent)
	if err != nil {
		// The client's half of the same punch failed too, and it is already falling to
		// the floor, which the libp2p handler is serving.
		logTierAttempt(opts, negotiate.TierWireGuard, tier.OutcomePunchFailed, time.Since(start), err)
		return
	}
	defer punched.agent.Close()

	// Reset rather than close on the way out. The last read on this stream is only
	// guaranteed to unblock on a reset, and by here the tier is going away regardless;
	// the deferred Close in negotiateTierHost is then a no-op.
	defer s.Reset()

	session := tierSession(deps.transport.Network(), peerHello, punched)

	pending, err := receiveRungRequest(ctx, x)
	for err == nil {
		if pending.Tier == negotiate.TierLibp2p {
			return
		}

		rungStart := time.Now()
		if err = sendRungAck(ctx, x, pending.Tier); err != nil {
			return
		}

		rung, outcome, standErr := deps.tiers.set.Serve(ctx, pending.Tier, punched.conn, session)
		if standErr != nil {
			// Nothing is signalled back: the client is running the same rung on the same
			// substrate and is finding out for itself. Wait for it to name the next one.
			logTierAttempt(opts, pending.Tier, outcome, time.Since(rungStart), standErr)
			if outcome == tier.OutcomeSubstrateAbandoned {
				// There is no substrate left to stand anything else up on, so waiting for
				// the client's next request would only produce an acknowledgement this
				// side cannot honour. Returning resets the stream, which is what tells the
				// client to stop climbing - the same signal it gets from any other host
				// that cannot continue.
				return
			}
			pending, err = receiveRungRequest(ctx, x)
			continue
		}
		logTierAttempt(opts, pending.Tier, outcome, time.Since(rungStart), nil)
		logTierSelected(pending.Tier)

		pending, err = serveRung(ctx, x, activeRung{id: pending.Tier, rung: rung}, deps, s)
	}
}

// receiveRungRequest waits for the client to name the next rung, under a deadline: a
// client that opened the stream and then stalled must not pin this handler for the
// process lifetime. The read that happens *while* a rung is being served is the one
// exception and is deliberately unbounded - see serveRung.
func receiveRungRequest(ctx context.Context, x *negotiate.Exchange) (negotiate.Attempt, error) {
	ctx, cancel := context.WithTimeout(ctx, negotiateTimeout)
	defer cancel()
	return x.ReceiveAttempt(ctx)
}

func sendRungAck(ctx context.Context, x *negotiate.Exchange, id negotiate.Tier) error {
	ctx, cancel := context.WithTimeout(ctx, negotiateTimeout)
	defer cancel()
	return x.SendAttempt(ctx, negotiate.Attempt{Tier: id})
}

// activeRung is a live rung together with the tier that built it.
//
// tier.Rung deliberately carries no ID of its own: an implementation is asked to
// build a data plane, not to label it, and the answer is something the caller
// already knows - it is what the caller asked for. Pairing them here keeps the
// host's own bookkeeping (session registration, log lines) naming the tier without
// making every implementation restate it.
type activeRung struct {
	id   negotiate.Tier
	rung tier.Rung
}

// serveRung serves one rung until the peer goes away or names a different one, then
// tears it down and reports what it read. A returned error means there is no next
// rung: the stream broke, or this process is shutting down.
//
// Watching the negotiate stream is how both of those arrive, and unifying them is the
// point. The client sends nothing more once its rung is up, so any message at all
// means it fell back, and any error means it is gone - a single blocking read covers
// the peer-gone watch and the fallback signal at once. It is deliberately unbounded:
// a healthy tunnel is silent here for its whole life.
func serveRung(ctx context.Context, x *negotiate.Exchange, active activeRung, deps hostTierDeps, s network.Stream) (negotiate.Attempt, error) {
	remote := s.Conn().RemotePeer()

	// tierCtx is what every part of the rung unwinds from, whether the trigger is this
	// process shutting down (ctx), the client moving on, the accept loop dying, or an
	// operator DISCONNECT reaching the registered stop.
	tierCtx, stopTier := context.WithCancel(ctx)
	defer stopTier()

	entry := deps.session.RegisterTier(remote, active.id, stopTier)
	defer deps.session.UnregisterTier(remote, entry)

	var live streamSet
	var serving sync.WaitGroup
	// Read only after serving.Wait(), which is what makes the unsynchronised write safe.
	var teardownErr error
	serving.Go(func() {
		<-tierCtx.Done()
		// Closing the rung is what unblocks the accept loop. Closing the live streams is
		// what unblocks forwards already in flight, and it is not optional: a WireGuard
		// device that stops passing packets leaves an established virtual conn blocked
		// in Read forever, so the handler wait below would never return.
		teardownErr = active.rung.Close()
		live.closeAll()
	})
	serving.Go(func() {
		defer stopTier()
		acceptRung(tierCtx, active, s.Conn(), deps, &live)
	})

	type request struct {
		attempt negotiate.Attempt
		err     error
	}
	// Buffered so the reader never blocks on a result nobody is waiting for any more.
	next := make(chan request, 1)
	serving.Go(func() {
		attempt, err := x.ReceiveAttempt(tierCtx)
		next <- request{attempt, err}
	})

	var got request
	select {
	case got = <-next:
	case <-tierCtx.Done():
		// The rung ended for a reason other than the client: the abandoned decode is
		// still in flight, so the exchange must not be reused. Reporting an error is
		// what stops the caller from trying.
		got = request{err: context.Cause(tierCtx)}
	}
	stopTier()
	serving.Wait()
	if got.err == nil && deps.tiers.set.SubstrateAbandoned(teardownErr) {
		// The client is asking for the next rung and this side no longer has anything to
		// stand it up on. Reported as an error because that is already this function's
		// contract for "there is no next rung", and because acknowledging a tier the host
		// cannot serve would strand the client waiting on a handshake that never comes.
		return negotiate.Attempt{}, teardownErr
	}
	return got.attempt, got.err
}

// acceptRung serves one rung's forwarded connections. It mirrors the libp2p data
// handler exactly - one forwarded connection per accepted stream, counted by the same
// SessionManager - so CONNECTED and DISCONNECT stay one-per-peer regardless of which
// tier the peer arrived on.
//
// signal is the peer's libp2p connection, which still exists: it carried the
// negotiation and is what the session's address is reported from.
func acceptRung(ctx context.Context, active activeRung, signal network.Conn, deps hostTierDeps, live *streamSet) {
	var handlers sync.WaitGroup
	defer handlers.Wait()

	remote := signal.RemotePeer()
	for {
		s, err := active.rung.Acceptor.AcceptStream(ctx)
		if err != nil {
			if ctx.Err() == nil {
				log.Printf("%s listener for %s stopped: %v", active.id, remote, err)
			}
			return
		}
		// Register before serving, so a teardown racing this accept closes the stream
		// instead of leaving a forward nothing will ever unblock.
		if !live.add(s) {
			_ = s.Close()
			return
		}
		if !deps.session.BeginStream(remote, signal) {
			// The host is shutting down and no longer serving connections.
			live.remove(s)
			_ = s.Close()
			return
		}
		handlers.Go(func() {
			defer deps.session.EndStream(remote)
			defer live.remove(s)
			handleHostStream(ctx, deps.transport, s, remote, deps.localAddr)
		})
	}
}

// streamSet tracks the forwarded connections a rung has accepted but not yet
// finished. It exists so a rung teardown can unblock every in-flight forward at once,
// which is the job SessionManager.Shutdown does for the libp2p tier by resetting its
// streams. Closing a listener only stops new connections, and closing a WireGuard
// device only stops packets arriving - neither releases a forward already blocked in
// Read.
//
// Streams are used as map keys, so every transport.Stream implementation has to be
// comparable. All of them are - each wraps a pointer or a single interface field -
// and a future one that is not would panic here rather than fail quietly.
type streamSet struct {
	mu      sync.Mutex
	streams map[transport.Stream]struct{}
	// closed makes the race between closeAll and a fresh accept safe in either
	// order: once set, add refuses rather than admitting a stream to a set nothing
	// will close again.
	closed bool
}

// add registers s and reports whether the caller may serve it.
func (set *streamSet) add(s transport.Stream) bool {
	set.mu.Lock()
	defer set.mu.Unlock()

	if set.closed {
		return false
	}
	if set.streams == nil {
		set.streams = make(map[transport.Stream]struct{})
	}
	set.streams[s] = struct{}{}
	return true
}

// remove drops s from the set. The caller closes it; a forward that ended on its own
// has already done so.
func (set *streamSet) remove(s transport.Stream) {
	set.mu.Lock()
	defer set.mu.Unlock()

	delete(set.streams, s)
}

// closeAll closes every registered stream and permanently refuses further adds.
func (set *streamSet) closeAll() {
	set.mu.Lock()
	set.closed = true
	streams := set.streams
	set.streams = nil
	set.mu.Unlock()

	// Outside the lock: Close can block, and the handlers it releases call remove.
	for s := range streams {
		_ = s.Close()
	}
}

// probeAgreed reports whether both sides asked for the punch probe. Requiring both
// is what keeps the stream in lockstep: the probe adds a second message to the
// exchange, so one side running it while the other does not would leave a reader
// waiting for a message that never comes.
func probeAgreed(local, peer negotiate.Hello) bool {
	return local.PunchProbe && peer.PunchProbe
}

// punchAgent is the slice of nat.Agent the ladder uses. It exists as an interface so
// tests can drive every phase of a punch - including the failure orderings that
// matter most - without real sockets, STUN servers, or NATs.
type punchAgent interface {
	Local() nat.Credentials
	AddRemote(remote nat.Credentials) error
	Connect(ctx context.Context, controlling bool) (net.Conn, error)
	Close() error
}

// punchFactory creates one punch attempt's agent.
type punchFactory func(ctx context.Context, cfg nat.Config) (punchAgent, error)

// newPunchAgent is the production factory. It converts the concrete failure into a
// genuinely nil interface: returning the *nat.Agent directly would hand back a
// non-nil interface wrapping a nil pointer, and the ladder's nil check would miss it.
func newPunchAgent(ctx context.Context, cfg nat.Config) (punchAgent, error) {
	agent, err := nat.New(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return agent, nil
}

// punchResult is one completed Rung A: the substrate every rung above shares, the
// agent that owns it, and the peer's QUIC certificate fingerprint, which travels
// alongside the ICE credentials because both are needed at the same moment and the
// stream carrying them is already authenticated.
//
// conn and agent are not separable - the conn is a view onto the agent's sockets - so
// the caller has to keep the agent alive for as long as it uses the conn, and closing
// the agent is what finally releases it.
type punchResult struct {
	conn            net.Conn
	agent           punchAgent
	peerFingerprint [32]byte
}

// errNegotiateStream marks a punch failure that happened on the negotiate stream
// rather than in ICE.
//
// The distinction matters to the retry loop and nowhere else: every other failure is a
// local one both sides can recover from by trying again, but a stream failure has
// destroyed the channel the two sides would have to agree over. Answering it with
// another message cannot resynchronise anything, so it ends the punch immediately.
var errNegotiateStream = errors.New("negotiate stream failed")

// punch runs Rung A: gather this side's ICE candidates, swap them with the peer over
// the negotiate stream's second phase, and run connectivity checks - retrying the whole
// sequence, in lockstep with the peer, up to attempts times.
//
// Both roles call it for the same resolved cascade and both must call it: the swap is
// a message on a shared stream, so one side skipping it strands the other. That is also
// why the retry cannot be a local decision. The two sides run separate ICE agents
// against separate NATs and do not have to fail together - the client's Connect can land
// microseconds before the host's context expires - so after each attempt they swap a
// negotiate.PunchOutcome and continue only if *both* landed a substrate. Without that,
// the side that succeeded would go on to send an Attempt while the side that failed
// looped back to gather, and the stream would be carrying two different message types
// in each direction.
//
// attempts of 0 or 1 skips the outcome swap entirely, leaving the wire byte-identical
// to a peer that predates the field - see negotiate.EffectivePunchAttempts, which is
// what both sides use to arrive at the same number without another round trip.
//
// fingerprint is this side's QUIC certificate hash, sent whether or not the QUIC rung
// is ever reached - the message shape stays the same on every path. On failure
// everything is already released.
func punch(ctx context.Context, x *negotiate.Exchange, opts Options, controlling bool, peerID string, fingerprint [32]byte, attempts uint8, newAgent punchFactory) (punchResult, error) {
	if attempts == 0 {
		attempts = 1
	}

	for attempt := uint8(1); ; attempt++ {
		result, err := punchOnce(ctx, x, opts, controlling, peerID, fingerprint, newAgent)

		// One agreed attempt is today's behaviour exactly, down to the bytes on the
		// stream. Nothing below runs.
		if attempts == 1 {
			return result, err
		}
		if errors.Is(err, errNegotiateStream) {
			return punchResult{}, err
		}

		outcomeCtx, cancel := context.WithTimeout(ctx, punchExchangeTimeout)
		agreed, swapErr := x.ExchangePunchOutcome(outcomeCtx, err == nil)
		cancel()
		if swapErr != nil {
			releasePunch(result)
			return punchResult{}, fmt.Errorf("%w: %w", errNegotiateStream, swapErr)
		}
		if agreed {
			// agreed implies this side succeeded, so result holds a live agent.
			return result, nil
		}

		// Either side may be the one that failed. Release whatever this side has -
		// a substrate the peer does not share is not a substrate - and let the ICE
		// agent go, since credentials are per-attempt and nat.Agent is not reusable.
		releasePunch(result)
		if err == nil {
			err = errors.New("peer's punch did not land")
		}

		if attempt >= attempts {
			return punchResult{}, err
		}
		slog.Warn("tunnel_punch_retry",
			"attempt", attempt,
			"attempts", attempts,
			"peer", peerID,
			"error", err.Error(),
		)
	}
}

// releasePunch closes whatever a punch attempt produced. Closing the agent is what
// releases the conn, which is only a view onto the agent's sockets.
func releasePunch(result punchResult) {
	if result.agent != nil {
		_ = result.agent.Close()
	}
}

// punchOnce is one pass of the sequence punch retries: gather, swap credentials, check
// connectivity. On failure everything it created is already released.
func punchOnce(ctx context.Context, x *negotiate.Exchange, opts Options, controlling bool, peerID string, fingerprint [32]byte, newAgent punchFactory) (punchResult, error) {
	agent, err := newAgent(ctx, nat.Config{
		STUNServers:   opts.STUNServers,
		Timeout:       opts.PunchTimeout,
		GatherTimeout: opts.PunchGatherTimeout,
		Diagnostic:    opts.P2P.Diagnostic,
	})
	// A factory that reports neither an agent nor an error is a bug, not a runtime
	// condition; treat it as a gather failure rather than dereference it. The
	// production factory cannot produce this, but the seam exists for test doubles
	// and a panic here would fire inside a stream handler.
	if err == nil && agent == nil {
		err = errors.New("punch factory returned no agent and no error")
	}

	var local nat.Credentials
	if err != nil {
		logPunchProbe(opts, punchGatherFailed, controlling, peerID, err)
	} else {
		local = agent.Local()
	}

	// Send even after a local gather failure. The peer is blocked in its own half of
	// this exchange, and empty credentials tell it to give up immediately instead of
	// waiting out the full timeout on a punch that was never going to happen.
	exchangeCtx, cancel := context.WithTimeout(ctx, punchExchangeTimeout)
	defer cancel()
	peerInfo, exchangeErr := x.ExchangePunchInfo(exchangeCtx, toPunchInfo(local, fingerprint))
	if exchangeErr != nil {
		logPunchProbe(opts, punchExchangeFailed, controlling, peerID, exchangeErr)
		if agent != nil {
			_ = agent.Close()
		}
		// Marked, not merely returned: this is the one failure here that is not worth
		// retrying, because it is the channel the two sides would retry over that broke.
		return punchResult{}, fmt.Errorf("%w: %w", errNegotiateStream, exchangeErr)
	}
	if err != nil {
		// Already reported as gather-failed; the send above was purely for the peer.
		// The nil check matches the exchange path above: a factory that reports an
		// agent alongside an error still handed one over, and this function promises
		// it releases everything on failure.
		if agent != nil {
			_ = agent.Close()
		}
		return punchResult{}, err
	}

	remote := fromPunchInfo(peerInfo)
	if !remote.Valid() {
		logPunchProbe(opts, punchPeerUnavailable, controlling, peerID, nil)
		_ = agent.Close()
		return punchResult{}, errors.New("peer reported no usable ICE credentials")
	}
	if err := agent.AddRemote(remote); err != nil {
		logPunchProbe(opts, punchRemoteRejected, controlling, peerID, err)
		_ = agent.Close()
		return punchResult{}, err
	}

	// Connect emits tunnel_nat_punch for both outcomes, with the candidate detail
	// this function does not have, so neither branch logs again here.
	conn, err := agent.Connect(ctx, controlling)
	if err != nil {
		_ = agent.Close()
		return punchResult{}, err
	}
	return punchResult{conn: conn, agent: agent, peerFingerprint: peerFingerprint(peerInfo)}, nil
}

// runPunchProbe performs a measurement-only punch and discards whatever it produces.
// Nothing depends on the result: the session it runs alongside is already on the
// libp2p floor either way. The point is to keep learning how often an independent
// ICE punch succeeds against real NATs even in sessions that never needed one.
//
// It sends a zero certificate fingerprint because it will never build a QUIC tier to
// pin, and the peer - running the same probe, on the same floor - has nothing to check
// it against.
//
// It never returns an error because there is nothing a caller could do with one.
//
// It always punches once, whatever -punch-attempts says, and both sides do the same so
// the stream stays symmetric. Retrying would corrupt the measurement: the number worth
// collecting is how often a single punch lands, which is what the cascade's first
// attempt faces.
func runPunchProbe(ctx context.Context, x *negotiate.Exchange, opts Options, controlling bool, peerID string, newAgent punchFactory) {
	punched, err := punch(ctx, x, opts, controlling, peerID, [32]byte{}, 1, newAgent)
	if err != nil {
		return
	}
	// Reaching this point is the whole result. Closing the agent would release the
	// conn anyway; closing both keeps the discard deliberate rather than incidental.
	_ = punched.conn.Close()
	_ = punched.agent.Close()
}

// toPunchInfo and fromPunchInfo translate between the punch package's credentials
// and the negotiate wire message. internal/nat deliberately does not import
// internal/negotiate - it has no opinion on how its credentials travel - so this
// translation is the tunnel package's job.
func toPunchInfo(c nat.Credentials, fingerprint [32]byte) negotiate.PunchInfo {
	return negotiate.PunchInfo{
		ICEUfrag:      c.Ufrag,
		ICEPwd:        c.Pwd,
		ICECandidates: c.Candidates,
		// Copied rather than sliced: the wire message outlives this call, and aliasing
		// the caller's array would let a later write change what was sent.
		QUICCertFingerprint: append([]byte(nil), fingerprint[:]...),
	}
}

func fromPunchInfo(info negotiate.PunchInfo) nat.Credentials {
	return nat.Credentials{
		Ufrag:      info.ICEUfrag,
		Pwd:        info.ICEPwd,
		Candidates: info.ICECandidates,
	}
}

// peerFingerprint reads the peer's QUIC certificate hash out of the wire message. A
// value of the wrong length - or one a peer predating the QUIC tier never sent -
// leaves the zero fingerprint, which quictun rejects with an error naming the missing
// value rather than a mismatch.
func peerFingerprint(info negotiate.PunchInfo) [32]byte {
	var fp [32]byte
	if len(info.QUICCertFingerprint) != len(fp) {
		return fp
	}
	copy(fp[:], info.QUICCertFingerprint)
	return fp
}

// logTierNegotiated emits the tunnel_tier_negotiated diagnostic record, gated behind
// the -diagnostic flag and following the slog.Info convention used elsewhere.
func logTierNegotiated(cfg p2p.Config, local, peer negotiate.Hello, selected negotiate.Tier) {
	if !cfg.Diagnostic {
		return
	}
	slog.Info("tunnel_tier_negotiated",
		"tunnel_mode", string(cfg.TunnelMode),
		"local_supported_tiers", tiersToStrings(local.SupportedTiers),
		"peer_supported_tiers", tiersToStrings(peer.SupportedTiers),
		"shared_cascade", tiersToStrings(negotiate.SharedCascade(local.SupportedTiers, peer.SupportedTiers)),
		"resolved_tier", string(selected),
		"punch_probe", probeAgreed(local, peer),
	)
}

// logTierAttempt records one rung of the fallback ladder: which tier was tried, how
// it ended, and how long it took to find out. The outcome names the phase that
// stopped it, because "wireguard failed" and "the punch never landed" call for very
// different investigations.
//
// A rung that failed is reported unconditionally, at Warn. Everything describing a
// fallback used to sit behind -diagnostic, which meant the one failure users actually
// report - "it worked, but slowly, over the relay" - was also the one failure that left
// no trace to report. The per-rung timeline stays behind the flag; the fact that a rung
// dropped, and which phase dropped it, does not.
func logTierAttempt(opts Options, id negotiate.Tier, outcome tier.Outcome, elapsed time.Duration, cause error) {
	attrs := []any{
		"tier", string(id),
		"outcome", string(outcome),
		"duration_ms", elapsed.Milliseconds(),
	}
	if cause != nil {
		attrs = append(attrs, "error", cause.Error())
	}

	if !outcome.Succeeded() {
		slog.Warn("tunnel_tier_fallback", attrs...)
	}
	if !opts.P2P.Diagnostic {
		return
	}
	slog.Info("tunnel_tier_attempt", attrs...)
}

// logTierSelected names the tier a session ended up on, unconditionally and once per
// side. It is the counterpart to tunnel_tier_fallback: the warnings say what did not
// work, this says what did - including negotiate.TierLibp2p, which is the case worth
// having, since a session on the floor is otherwise indistinguishable from a healthy
// one until someone measures the latency.
//
// The client emits it once, from negotiateTierClient's deferred call, so every path to
// the floor is covered rather than the ones someone remembered. The host emits it per
// rung it begins serving, which can legitimately fire more than once: when the client
// falls back, the host really does switch to a different tier.
func logTierSelected(selected negotiate.Tier) {
	slog.Info("tunnel_tier_selected", "tier", string(selected))
}

// punchPhase names a phase of the punch that ended before ICE connectivity checks
// began. Once checks start, internal/nat's own tunnel_nat_punch record is the
// authority and these no longer apply.
//
// A type rather than four literals because these are the vocabulary of the
// tunnel_nat_probe record: whoever reads that record has to know the whole set, and a
// set spelled out at each call site is one nobody can enumerate.
type punchPhase string

const (
	// punchGatherFailed is this side's ICE agent failing to produce candidates.
	punchGatherFailed punchPhase = "gather-failed"
	// punchExchangeFailed is the negotiate stream breaking during the credential swap.
	punchExchangeFailed punchPhase = "exchange-failed"
	// punchPeerUnavailable is the peer reporting no usable credentials - usually
	// because its own gathering failed and it said so rather than leaving this side to
	// time out.
	punchPeerUnavailable punchPhase = "peer-unavailable"
	// punchRemoteRejected is this side's agent refusing the peer's credentials.
	punchRemoteRejected punchPhase = "remote-rejected"
)

// punchRole names which side of ICE this is. Controlling is the client, which
// initiates everywhere else too.
type punchRole string

const (
	roleControlling punchRole = "controlling"
	roleControlled  punchRole = "controlled"
)

func punchRoleFor(controlling bool) punchRole {
	if controlling {
		return roleControlling
	}
	return roleControlled
}

// logPunchProbe records a punch that ended before ICE connectivity checks began.
func logPunchProbe(opts Options, phase punchPhase, controlling bool, peerID string, cause error) {
	if !opts.P2P.Diagnostic {
		return
	}
	attrs := []any{
		"outcome", string(phase),
		"role", string(punchRoleFor(controlling)),
		"peer", peerID,
	}
	if cause != nil {
		attrs = append(attrs, "error", cause.Error())
	}
	slog.Info("tunnel_nat_probe", attrs...)
}

func tiersToStrings(ids []negotiate.Tier) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = string(id)
	}
	return out
}
