package tunnel

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"mtunnel-libp2p/internal/nat"
	"mtunnel-libp2p/internal/negotiate"
	"mtunnel-libp2p/internal/p2p"
	"mtunnel-libp2p/internal/quictun"
	"mtunnel-libp2p/internal/transport"
	"mtunnel-libp2p/internal/wireguard"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// wireGuardKeys is one side's static X25519 identity for the WireGuard tier. Like
// the libp2p peer identity, it is generated fresh every run and never persisted.
// stdlib X25519 keys are byte-compatible with WireGuard's key format: both derive
// the public key with curve25519.X25519(scalar, basepoint), which clamps internally,
// so neither side has to clamp for the other.
type wireGuardKeys struct {
	private [32]byte
	public  [32]byte
}

func newWireGuardKeys() (wireGuardKeys, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return wireGuardKeys{}, fmt.Errorf("generate WireGuard keypair: %w", err)
	}
	var keys wireGuardKeys
	copy(keys.private[:], key.Bytes())
	copy(keys.public[:], key.PublicKey().Bytes())
	return keys, nil
}

// tierIdentities is every ephemeral credential this process needs for tiers above
// the floor, generated once at startup and reused for every session.
//
// Both are generated whatever the tunnel mode, for the same reason the WireGuard key
// always goes in the token: the mode decides which tiers this side *offers*, and a
// peer that withheld a credential would force the floor on a session that could have
// used something better. Neither is persisted, matching the libp2p peer identity -
// a restart is a new identity on every axis.
type tierIdentities struct {
	wg   wireGuardKeys
	quic *quictun.Identity
}

func newTierIdentities() (tierIdentities, error) {
	keys, err := newWireGuardKeys()
	if err != nil {
		return tierIdentities{}, err
	}
	id, err := quictun.NewIdentity()
	if err != nil {
		return tierIdentities{}, fmt.Errorf("generate QUIC identity: %w", err)
	}
	return tierIdentities{wg: keys, quic: id}, nil
}

// tierResult is what one peer session's negotiation and fallback ladder produced.
type tierResult struct {
	// tier is the rung that actually came up - not the one negotiation aimed at -
	// and is what the CONNECTED event reports.
	tier negotiate.Tier
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
	return tierResult{tier: negotiate.TierLibp2p, close: func() error { return nil }}
}

// forcesTier reports whether mode pins the session to one tier above the floor.
//
// Forcing changes nothing about selection - see supportedTiers - only what each side
// does when the forced tier does not come up: the client returns the error instead
// of falling back, and the host leaves the libp2p data handler unregistered so a
// client that fell back anyway finds nothing listening.
func forcesTier(mode p2p.TunnelMode) bool {
	return mode == p2p.TunnelWireGuard || mode == p2p.TunnelQUIC
}

// supportedTiers derives this side's advertised preference order from the tunnel
// mode. The libp2p floor is always last and always present, so a peer that supports
// nothing else still resolves to a working tunnel.
//
// Forcing narrows the list but does not remove the floor, which is what keeps tier
// selection a pure intersection with no special cases. What forcing actually changes
// is the response to failure: see climbCascade (hard failure) and RunHost (no libp2p
// data handler registered at all).
func supportedTiers(mode p2p.TunnelMode) []negotiate.Tier {
	switch mode {
	case p2p.TunnelAuto:
		return []negotiate.Tier{negotiate.TierWireGuard, negotiate.TierQUIC, negotiate.TierLibp2p}
	case p2p.TunnelWireGuard:
		return []negotiate.Tier{negotiate.TierWireGuard, negotiate.TierLibp2p}
	case p2p.TunnelQUIC:
		return []negotiate.Tier{negotiate.TierQUIC, negotiate.TierLibp2p}
	default:
		return []negotiate.Tier{negotiate.TierLibp2p}
	}
}

// datagramTier reports whether the forwarded network is message-oriented, which is
// what selects each upper tier's unreliable sub-mode: QUIC's DATAGRAM extension
// rather than QUIC streams, and WireGuard's virtual UDP conn rather than its virtual
// TCP listener.
//
// Both sides derive it from the same -network value carried in the token, so they
// cannot disagree.
func datagramTier(network string) bool {
	return network == "udp"
}

// localHello builds this side's negotiate.Hello. wgPubKey is this side's static
// X25519 public key; both roles now have one, since the WireGuard tier needs a key
// in each direction.
//
// punchProbe asks for the measurement-only NAT punch described on negotiate.Hello.
// It tracks the diagnostic flag because that probe exists only to produce diagnostic
// records - a session that negotiates a tier above the floor punches for real
// instead, and never runs the probe.
func localHello(wgPubKey [32]byte, mode p2p.TunnelMode, punchProbe bool) negotiate.Hello {
	return negotiate.Hello{
		SupportedTiers:  supportedTiers(mode),
		WireGuardPubKey: wgPubKey,
		PunchProbe:      punchProbe,
	}
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
// network name, which selects each tier's datagram sub-mode.
//
// wg tracks a background punch probe when one runs. The probe only happens on the
// floor - a session with a shared cascade punches for real, in the foreground.
func negotiateTierClient(ctx context.Context, h host.Host, target peer.ID, opts Options, ids tierIdentities, tokenWGPubKey [32]byte, network string, wg *sync.WaitGroup) (tierResult, error) {
	forced := forcesTier(opts.P2P.TunnelMode)

	stream, err := p2p.OpenNegotiateStream(ctx, h, target, opts.P2P)
	if err != nil {
		if forced {
			return libp2pFloor(), fmt.Errorf("open negotiate stream to %s: %w", target, err)
		}
		log.Printf("Tier negotiation with %s unavailable, using %s tier: %v", target, negotiate.TierLibp2p, err)
		return libp2pFloor(), nil
	}

	local := localHello(ids.wg.public, opts.P2P.TunnelMode, opts.P2P.Diagnostic)
	exchange := negotiate.NewExchange(stream)
	tier, peerHello, err := exchangeHello(ctx, exchange, local, negotiateTimeout)
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
	logTierNegotiated(opts.P2P, local, peerHello, tier)

	cascade := negotiate.SharedCascade(local.SupportedTiers, peerHello.SupportedTiers)

	// Both sides compute the same cascade and the same probeAgreed from the same pair
	// of Hellos, so both take the same branch here. That is what keeps the stream in
	// lockstep: the two upper branches each add messages to the exchange, and one side
	// taking a different branch would strand the other.
	switch {
	case cascade[0] != negotiate.TierLibp2p:
		result, err := climbCascade(ctx, exchange, opts, ids, peerHello, target, network, cascade, newPunchAgent)
		if err == nil {
			// The negotiate stream is the tier's lifeline: the host tears its half down
			// when the stream ends, so it stays open as long as the tunnel does.
			result.close = closeAll(result.close, stream.Close)
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
func climbCascade(ctx context.Context, x *negotiate.Exchange, opts Options, ids tierIdentities, peerHello negotiate.Hello, target peer.ID, network string, cascade []negotiate.Tier, newAgent punchFactory) (tierResult, error) {
	start := time.Now()
	punched, err := punch(ctx, x, opts, true, target.String(), ids.quic.Fingerprint, newAgent)
	if err != nil {
		logTierAttempt(opts, cascade[0], "punch-failed", time.Since(start), err)
		return tierResult{}, err
	}

	var lastErr error
	for _, tier := range cascade {
		if tier == negotiate.TierLibp2p {
			break
		}

		rungStart := time.Now()
		if err := requestRung(ctx, x, tier); err != nil {
			// The exchange is the only thing keeping the two sides in step, so a failure
			// here is not a failure of this rung - it means there is no longer a way to
			// agree on the next one either.
			logTierAttempt(opts, tier, "request-failed", time.Since(rungStart), err)
			_ = punched.agent.Close()
			return tierResult{}, err
		}

		rung, outcome, err := dialRung(ctx, tier, punched, opts, ids, peerHello, network)
		if err != nil {
			logTierAttempt(opts, tier, outcome, time.Since(rungStart), err)
			lastErr = err
			continue
		}
		logTierAttempt(opts, tier, "connected", time.Since(rungStart), nil)
		return tierResult{
			tier:   tier,
			opener: rung.opener,
			// The agent goes last: it owns the substrate every rung ran on, so releasing
			// it before the rung on top would pull the floor out from under a teardown
			// still in progress.
			close: closeAll(rung.close, punched.agent.Close),
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
func requestRung(ctx context.Context, x *negotiate.Exchange, tier negotiate.Tier) error {
	ctx, cancel := context.WithTimeout(ctx, negotiateTimeout)
	defer cancel()

	if err := x.SendAttempt(ctx, negotiate.Attempt{Tier: tier}); err != nil {
		return err
	}
	ack, err := x.ReceiveAttempt(ctx)
	if err != nil {
		return err
	}
	if ack.Tier != tier {
		return fmt.Errorf("host acknowledged tier %q for a %q attempt", ack.Tier, tier)
	}
	return nil
}

// clientRung is the client half of one rung: what opens forwarded connections over
// it, and what releases it. close never touches the shared substrate.
type clientRung struct {
	opener transport.Opener
	close  func() error
}

// dialRung builds the client half of one rung on the shared substrate. The returned
// outcome names the phase that ended the attempt, for the diagnostic record, and is
// meaningful only alongside a non-nil error.
func dialRung(ctx context.Context, tier negotiate.Tier, punched punchResult, opts Options, ids tierIdentities, peerHello negotiate.Hello, network string) (clientRung, string, error) {
	switch tier {
	case negotiate.TierWireGuard:
		return dialWireGuardClient(ctx, punched.conn, opts, ids.wg, peerHello, network)
	case negotiate.TierQUIC:
		return dialQUICClient(ctx, punched.conn, opts, ids.quic, punched.peerFingerprint, network)
	default:
		return clientRung{}, "unsupported", fmt.Errorf("no client implementation for tier %q", tier)
	}
}

// dialWireGuardClient brings up the client's WireGuard device and waits for the
// handshake that proves the tier works.
//
// Every failure path releases everything built so far, because the caller's answer to
// an error is to try a rung that shares none of it.
func dialWireGuardClient(ctx context.Context, substrate net.Conn, opts Options, keys wireGuardKeys, peerHello negotiate.Hello, network string) (clientRung, string, error) {
	tun, err := wireguard.New(substrate, wireguard.Config{
		PrivateKey:    keys.private,
		PeerPublicKey: peerHello.WireGuardPubKey,
		Local:         wireguard.ClientAddr,
		Peer:          wireguard.HostAddr,
		// The client initiates, as everywhere else. Both sides coming up at once makes
		// that asymmetry load-bearing rather than conventional - see
		// wireguard.Config.Initiate.
		Initiate:   true,
		Diagnostic: opts.P2P.Diagnostic,
	})
	if err != nil {
		return clientRung{}, "device-failed", err
	}

	rung := clientRung{close: tun.Close}
	if datagramTier(network) {
		// Open the virtual UDP conn before the device comes up, for the same reason the
		// host listens before it comes up: the endpoint has to exist before the first
		// packet can arrive at it.
		mux, err := tun.NewUDPMux(wireguard.ClientAddr, wireguard.HostAddr, true)
		if err != nil {
			_ = tun.Close()
			return clientRung{}, "mux-failed", err
		}
		rung.opener = mux
		rung.close = closeAll(mux.Close, tun.Close)
	} else {
		rung.opener = wireGuardOpener{
			tun:  tun,
			dest: netip.AddrPortFrom(wireguard.HostAddr, wireguard.VirtualPort),
		}
	}

	if err := tun.Up(); err != nil {
		_ = rung.close()
		return clientRung{}, "up-failed", err
	}
	if err := tun.WaitHandshake(ctx, opts.handshakeTimeout()); err != nil {
		_ = rung.close()
		return clientRung{}, "handshake-failed", err
	}
	return rung, "connected", nil
}

// dialQUICClient completes a QUIC handshake on the shared substrate. Unlike
// WireGuard there is no separate readiness wait: the handshake either completes
// within its own budget or the tier has failed.
func dialQUICClient(ctx context.Context, substrate net.Conn, opts Options, id *quictun.Identity, peerFingerprint [32]byte, network string) (clientRung, string, error) {
	tun, err := quictun.Dial(ctx, substrate, quicConfig(opts, id, peerFingerprint, network))
	if err != nil {
		return clientRung{}, "handshake-failed", err
	}
	return clientRung{opener: tun, close: tun.Close}, "connected", nil
}

// quicConfig is shared by both roles so the two sides cannot drift apart on datagram
// support, which is negotiated inside the handshake and fails the tier if it does not
// match.
func quicConfig(opts Options, id *quictun.Identity, peerFingerprint [32]byte, network string) quictun.Config {
	return quictun.Config{
		Identity:        id,
		PeerFingerprint: peerFingerprint,
		Datagrams:       datagramTier(network),
		// One budget covers every tier's handshake, so the ladder's worst case stays
		// predictable. It must also stay comfortably under negotiateTimeout: the host
		// spends it inside quictun.Accept, unable to read the next Attempt, and the
		// client is waiting for the acknowledgement of exactly that message.
		HandshakeTimeout: opts.handshakeTimeout(),
		Diagnostic:       opts.P2P.Diagnostic,
	}
}

// wireGuardOpener opens one virtual TCP connection to the host per forwarded local
// connection, mirroring exactly what streamOpener does with libp2p streams.
type wireGuardOpener struct {
	tun  *wireguard.Tunnel
	dest netip.AddrPort
}

func (o wireGuardOpener) OpenStream(ctx context.Context) (transport.Stream, error) {
	c, err := o.tun.DialTCP(ctx, o.dest)
	if err != nil {
		return nil, err
	}
	return transport.ConnStream{Conn: c}, nil
}

// hostTierDeps is what the host side needs to serve a forwarded connection, whatever
// tier it arrives on. It exists so the negotiate handler's signature does not grow a
// parameter per collaborator.
type hostTierDeps struct {
	session   *SessionManager
	transport transport.Transport
	localAddr string
}

// negotiateTierHost is the host side of the handshake, invoked from the
// NegotiateProtocolID stream handler. It owns the stream's lifetime, and when a tier
// above the floor is in play it keeps that stream open for as long as the tunnel
// lives - see serveUpperTiers.
//
// The host never chooses: it serves whichever rung the client asks for, and the
// client is the side that finds out a rung failed. The libp2p handler registered in
// RunHost stays live alongside an upper tier, so a client that exhausted the cascade
// is already served. The one exception is a forced -tunnel-mode, which leaves that
// handler unregistered so the fallback fails loudly.
func negotiateTierHost(ctx context.Context, opts Options, ids tierIdentities, deps hostTierDeps, s network.Stream) {
	defer s.Close()

	remote := s.Conn().RemotePeer()
	local := localHello(ids.wg.public, opts.P2P.TunnelMode, opts.P2P.Diagnostic)
	exchange := negotiate.NewExchange(s)
	tier, peerHello, err := exchangeHello(ctx, exchange, local, negotiateTimeout)
	if err != nil {
		// Reset rather than close: the peer should see a failed negotiation, not a
		// clean end-of-stream it might mistake for an empty answer.
		_ = s.Reset()
		log.Printf("Tier negotiation with %s failed: %v", remote, err)
		return
	}
	logTierNegotiated(opts.P2P, local, peerHello, tier)

	// Both sides compute the cascade and probeAgreed from the same pair of Hellos, so
	// both take the same branch here. That is what keeps the stream in lockstep: the
	// two upper branches each add messages to the exchange, and one side taking a
	// different branch would strand the other.
	switch {
	case tier != negotiate.TierLibp2p:
		serveUpperTiers(ctx, exchange, opts, ids, peerHello, deps, s)
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
func serveUpperTiers(ctx context.Context, x *negotiate.Exchange, opts Options, ids tierIdentities, peerHello negotiate.Hello, deps hostTierDeps, s network.Stream) {
	remote := s.Conn().RemotePeer()

	start := time.Now()
	punched, err := punch(ctx, x, opts, false, remote.String(), ids.quic.Fingerprint, newPunchAgent)
	if err != nil {
		// The client's half of the same punch failed too, and it is already falling to
		// the floor, which the libp2p handler is serving.
		logTierAttempt(opts, negotiate.TierWireGuard, "punch-failed", time.Since(start), err)
		return
	}
	defer punched.agent.Close()

	// Reset rather than close on the way out. The last read on this stream is only
	// guaranteed to unblock on a reset, and by here the tier is going away regardless;
	// the deferred Close in negotiateTierHost is then a no-op.
	defer s.Reset()

	pending, err := receiveRungRequest(ctx, x)
	for err == nil {
		if pending.Tier == negotiate.TierLibp2p {
			return
		}

		rungStart := time.Now()
		if err = sendRungAck(ctx, x, pending.Tier); err != nil {
			return
		}

		rung, outcome, standErr := standUpRung(ctx, pending.Tier, punched, opts, ids, peerHello, deps)
		if standErr != nil {
			// Nothing is signalled back: the client is running the same rung on the same
			// substrate and is finding out for itself. Wait for it to name the next one.
			logTierAttempt(opts, pending.Tier, outcome, time.Since(rungStart), standErr)
			pending, err = receiveRungRequest(ctx, x)
			continue
		}
		logTierAttempt(opts, pending.Tier, "serving", time.Since(rungStart), nil)

		pending, err = serveRung(ctx, x, rung, deps, s)
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

func sendRungAck(ctx context.Context, x *negotiate.Exchange, tier negotiate.Tier) error {
	ctx, cancel := context.WithTimeout(ctx, negotiateTimeout)
	defer cancel()
	return x.SendAttempt(ctx, negotiate.Attempt{Tier: tier})
}

// hostRung is the host half of one rung: where forwarded connections arrive, and what
// releases it. close never touches the shared substrate, which outlives every rung.
type hostRung struct {
	tier   negotiate.Tier
	accept streamAcceptor
	close  func() error
}

// streamAcceptor is the one thing a host-side tier has to offer: the next forwarded
// connection the peer started.
type streamAcceptor interface {
	AcceptStream(ctx context.Context) (transport.Stream, error)
}

// standUpRung builds the host half of one rung on the shared substrate. Like
// dialRung, the outcome names the phase that ended the attempt and is meaningful only
// alongside a non-nil error.
func standUpRung(ctx context.Context, tier negotiate.Tier, punched punchResult, opts Options, ids tierIdentities, peerHello negotiate.Hello, deps hostTierDeps) (hostRung, string, error) {
	switch tier {
	case negotiate.TierWireGuard:
		return standUpWireGuardHost(punched.conn, opts, ids.wg, peerHello, deps.transport.Network())
	case negotiate.TierQUIC:
		return standUpQUICHost(ctx, punched.conn, opts, ids.quic, punched.peerFingerprint, deps.transport.Network())
	default:
		return hostRung{}, "unsupported", fmt.Errorf("no host implementation for tier %q", tier)
	}
}

func standUpWireGuardHost(substrate net.Conn, opts Options, keys wireGuardKeys, peerHello negotiate.Hello, network string) (hostRung, string, error) {
	tun, err := wireguard.New(substrate, wireguard.Config{
		PrivateKey:    keys.private,
		PeerPublicKey: peerHello.WireGuardPubKey,
		Local:         wireguard.HostAddr,
		Peer:          wireguard.ClientAddr,
		Diagnostic:    opts.P2P.Diagnostic,
	})
	if err != nil {
		return hostRung{}, "device-failed", err
	}

	rung := hostRung{tier: negotiate.TierWireGuard}
	// Listen before Up: the client dials this address the moment its handshake
	// completes, and a device that came up first would answer that dial with a reset -
	// or, for UDP, with an ICMP port-unreachable that discards the first datagram.
	if datagramTier(network) {
		mux, err := tun.NewUDPMux(wireguard.HostAddr, wireguard.ClientAddr, false)
		if err != nil {
			_ = tun.Close()
			return hostRung{}, "mux-failed", err
		}
		rung.accept = mux
		rung.close = closeAll(mux.Close, tun.Close)
	} else {
		ln, err := tun.ListenTCP(netip.AddrPortFrom(wireguard.HostAddr, wireguard.VirtualPort))
		if err != nil {
			_ = tun.Close()
			return hostRung{}, "listen-failed", err
		}
		rung.accept = listenerAcceptor{ln: ln}
		rung.close = closeAll(ln.Close, tun.Close)
	}

	if err := tun.Up(); err != nil {
		_ = rung.close()
		return hostRung{}, "up-failed", err
	}
	return rung, "serving", nil
}

func standUpQUICHost(ctx context.Context, substrate net.Conn, opts Options, id *quictun.Identity, peerFingerprint [32]byte, network string) (hostRung, string, error) {
	tun, err := quictun.Accept(ctx, substrate, quicConfig(opts, id, peerFingerprint, network))
	if err != nil {
		return hostRung{}, "handshake-failed", err
	}
	return hostRung{tier: negotiate.TierQUIC, accept: tun, close: tun.Close}, "serving", nil
}

// listenerAcceptor adapts a virtual TCP listener to streamAcceptor. The context is
// ignored because a netstack listener has no context-aware Accept; closing it is what
// unblocks the call, which is exactly what the rung's teardown does.
type listenerAcceptor struct {
	ln net.Listener
}

func (a listenerAcceptor) AcceptStream(context.Context) (transport.Stream, error) {
	c, err := a.ln.Accept()
	if err != nil {
		return nil, err
	}
	return transport.ConnStream{Conn: c}, nil
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
func serveRung(ctx context.Context, x *negotiate.Exchange, rung hostRung, deps hostTierDeps, s network.Stream) (negotiate.Attempt, error) {
	remote := s.Conn().RemotePeer()

	// tierCtx is what every part of the rung unwinds from, whether the trigger is this
	// process shutting down (ctx), the client moving on, the accept loop dying, or an
	// operator DISCONNECT reaching the registered stop.
	tierCtx, stopTier := context.WithCancel(ctx)
	defer stopTier()

	entry := deps.session.RegisterTier(remote, rung.tier, stopTier)
	defer deps.session.UnregisterTier(remote, entry)

	var live streamSet
	var serving sync.WaitGroup
	serving.Go(func() {
		<-tierCtx.Done()
		// Closing the rung is what unblocks the accept loop. Closing the live streams is
		// what unblocks forwards already in flight, and it is not optional: a WireGuard
		// device that stops passing packets leaves an established virtual conn blocked
		// in Read forever, so the handler wait below would never return.
		_ = rung.close()
		live.closeAll()
	})
	serving.Go(func() {
		defer stopTier()
		acceptRung(tierCtx, rung, s.Conn(), deps, &live)
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
	return got.attempt, got.err
}

// acceptRung serves one rung's forwarded connections. It mirrors the libp2p data
// handler exactly - one forwarded connection per accepted stream, counted by the same
// SessionManager - so CONNECTED and DISCONNECT stay one-per-peer regardless of which
// tier the peer arrived on.
//
// signal is the peer's libp2p connection, which still exists: it carried the
// negotiation and is what the session's address is reported from.
func acceptRung(ctx context.Context, rung hostRung, signal network.Conn, deps hostTierDeps, live *streamSet) {
	var handlers sync.WaitGroup
	defer handlers.Wait()

	remote := signal.RemotePeer()
	for {
		s, err := rung.accept.AcceptStream(ctx)
		if err != nil {
			if ctx.Err() == nil {
				log.Printf("%s listener for %s stopped: %v", rung.tier, remote, err)
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

// closeAll composes teardown functions into one that runs all of them in order and
// reports the first error. Every step runs even if an earlier one failed: these are
// resource releases, and skipping the rest to report a failure leaks.
func closeAll(fns ...func() error) func() error {
	return func() error {
		var first error
		for _, fn := range fns {
			if err := fn(); err != nil && first == nil {
				first = err
			}
		}
		return first
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

// punch runs Rung A: gather this side's ICE candidates, swap them with the peer over
// the negotiate stream's second phase, and run connectivity checks.
//
// Both roles call it for the same resolved cascade and both must call it: the swap is
// a message on a shared stream, so one side skipping it strands the other.
//
// fingerprint is this side's QUIC certificate hash, sent whether or not the QUIC rung
// is ever reached - the message shape stays the same on every path. On failure
// everything is already released.
func punch(ctx context.Context, x *negotiate.Exchange, opts Options, controlling bool, peerID string, fingerprint [32]byte, newAgent punchFactory) (punchResult, error) {
	agent, err := newAgent(ctx, nat.Config{
		STUNServers: opts.STUNServers,
		Timeout:     opts.PunchTimeout,
		Diagnostic:  opts.P2P.Diagnostic,
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
		logPunchProbe(opts, "gather-failed", controlling, peerID, err)
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
		logPunchProbe(opts, "exchange-failed", controlling, peerID, exchangeErr)
		if agent != nil {
			_ = agent.Close()
		}
		return punchResult{}, exchangeErr
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
		logPunchProbe(opts, "peer-unavailable", controlling, peerID, nil)
		_ = agent.Close()
		return punchResult{}, errors.New("peer reported no usable ICE credentials")
	}
	if err := agent.AddRemote(remote); err != nil {
		logPunchProbe(opts, "remote-rejected", controlling, peerID, err)
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
func runPunchProbe(ctx context.Context, x *negotiate.Exchange, opts Options, controlling bool, peerID string, newAgent punchFactory) {
	punched, err := punch(ctx, x, opts, controlling, peerID, [32]byte{}, newAgent)
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
func logTierNegotiated(cfg p2p.Config, local, peer negotiate.Hello, tier negotiate.Tier) {
	if !cfg.Diagnostic {
		return
	}
	slog.Info("tunnel_tier_negotiated",
		"tunnel_mode", string(cfg.TunnelMode),
		"local_supported_tiers", tiersToStrings(local.SupportedTiers),
		"peer_supported_tiers", tiersToStrings(peer.SupportedTiers),
		"shared_cascade", tiersToStrings(negotiate.SharedCascade(local.SupportedTiers, peer.SupportedTiers)),
		"resolved_tier", string(tier),
		"punch_probe", probeAgreed(local, peer),
	)
}

// logTierAttempt records one rung of the fallback ladder: which tier was tried, how
// it ended, and how long it took to find out. The outcome names the phase that
// stopped it, because "wireguard failed" and "the punch never landed" call for very
// different investigations.
func logTierAttempt(opts Options, tier negotiate.Tier, outcome string, elapsed time.Duration, cause error) {
	if !opts.P2P.Diagnostic {
		return
	}
	attrs := []any{
		"tier", string(tier),
		"outcome", outcome,
		"duration_ms", elapsed.Milliseconds(),
	}
	if cause != nil {
		attrs = append(attrs, "error", cause.Error())
	}
	slog.Info("tunnel_tier_attempt", attrs...)
}

// logPunchProbe records a punch that ended before ICE connectivity checks began.
// Once checks start, internal/nat's own tunnel_nat_punch record is the authority.
func logPunchProbe(opts Options, outcome string, controlling bool, peerID string, cause error) {
	if !opts.P2P.Diagnostic {
		return
	}
	attrs := []any{
		"outcome", outcome,
		"role", map[bool]string{true: "controlling", false: "controlled"}[controlling],
		"peer", peerID,
	}
	if cause != nil {
		attrs = append(attrs, "error", cause.Error())
	}
	slog.Info("tunnel_nat_probe", attrs...)
}

func tiersToStrings(tiers []negotiate.Tier) []string {
	out := make([]string, len(tiers))
	for i, t := range tiers {
		out[i] = string(t)
	}
	return out
}
