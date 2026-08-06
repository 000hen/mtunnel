package tier

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"mtunnel-libp2p/internal/negotiate"
	"mtunnel-libp2p/internal/transport"
	"mtunnel-libp2p/internal/wireguard"
)

// wireGuardTier is the preferred rung: a WireGuard device over the punched
// substrate, with a netstack TCP listener or virtual UDP conn on top.
type wireGuardTier struct {
	keys   WireGuardIdentity
	params Params
}

// newWireGuard returns the WireGuard tier, holding this process's static X25519
// identity for every session it will serve. It is unexported because a tier is
// reached through a Set, which is what pairs it with the right credential.
func newWireGuard(keys WireGuardIdentity, params Params) Tier {
	return wireGuardTier{keys: keys, params: params}
}

func (wireGuardTier) ID() negotiate.Tier { return negotiate.TierWireGuard }

func (wireGuardTier) SubstrateAbandoned(err error) bool {
	return errors.Is(err, wireguard.ErrSubstrateAbandoned)
}

// Dial brings up the client's WireGuard device and waits for the handshake that
// proves the tier works.
//
// Every failure path releases everything built so far, because the caller's
// answer to an error is to try a rung that shares none of it.
func (t wireGuardTier) Dial(ctx context.Context, substrate net.Conn, s Session) (Rung, Outcome, error) {
	tun, err := wireguard.New(substrate, wireguard.Config{
		PrivateKey:    t.keys.Private,
		PeerPublicKey: s.PeerWireGuardKey,
		Local:         wireguard.ClientAddr,
		Peer:          wireguard.HostAddr,
		// The client initiates, as everywhere else. Both sides coming up at once
		// makes that asymmetry load-bearing rather than conventional - see
		// wireguard.Config.Initiate.
		Initiate:   true,
		Diagnostic: t.params.Diagnostic,
	})
	if err != nil {
		return Rung{}, OutcomeDeviceFailed, err
	}

	rung := Rung{Close: tun.Close}
	if s.Network.Datagram() {
		// Open the virtual UDP conn before the device comes up, for the same reason
		// the host listens before it comes up: the endpoint has to exist before the
		// first packet can arrive at it.
		mux, err := tun.NewUDPMux(wireguard.ClientAddr, wireguard.HostAddr, true)
		if err != nil {
			return failed(t, tun.Close, OutcomeMuxFailed, err)
		}
		rung.Opener = mux
		rung.Close = CloseAll(mux.Close, tun.Close)
	} else {
		rung.Opener = wireGuardOpener{
			tun:  tun,
			dest: netip.AddrPortFrom(wireguard.HostAddr, wireguard.VirtualPort),
		}
	}

	if err := tun.Up(); err != nil {
		return failed(t, rung.Close, OutcomeUpFailed, err)
	}
	if err := tun.WaitHandshake(ctx, t.params.handshakeTimeout()); err != nil {
		// The one that matters in the field: a handshake that never lands leaves the
		// device's receive loop parked in the substrate's Read, which is precisely
		// the state whose teardown can end up closing the substrate.
		return failed(t, rung.Close, OutcomeHandshakeFailed, err)
	}
	return rung, OutcomeConnected, nil
}

// Serve stands up the host's WireGuard device. Unlike Dial there is no handshake
// wait: the host is ready as soon as it is listening, and the client is the side
// that finds out whether the tier actually works.
func (t wireGuardTier) Serve(_ context.Context, substrate net.Conn, s Session) (Rung, Outcome, error) {
	tun, err := wireguard.New(substrate, wireguard.Config{
		PrivateKey:    t.keys.Private,
		PeerPublicKey: s.PeerWireGuardKey,
		Local:         wireguard.HostAddr,
		Peer:          wireguard.ClientAddr,
		Diagnostic:    t.params.Diagnostic,
	})
	if err != nil {
		return Rung{}, OutcomeDeviceFailed, err
	}

	var rung Rung
	// Listen before Up: the client dials this address the moment its handshake
	// completes, and a device that came up first would answer that dial with a
	// reset - or, for UDP, with an ICMP port-unreachable that discards the first
	// datagram.
	if s.Network.Datagram() {
		mux, err := tun.NewUDPMux(wireguard.HostAddr, wireguard.ClientAddr, false)
		if err != nil {
			return failed(t, tun.Close, OutcomeMuxFailed, err)
		}
		rung.Acceptor = mux
		rung.Close = CloseAll(mux.Close, tun.Close)
	} else {
		ln, err := tun.ListenTCP(netip.AddrPortFrom(wireguard.HostAddr, wireguard.VirtualPort))
		if err != nil {
			return failed(t, tun.Close, OutcomeListenFailed, err)
		}
		rung.Acceptor = listenerAcceptor{ln: ln}
		rung.Close = CloseAll(ln.Close, tun.Close)
	}

	if err := tun.Up(); err != nil {
		return failed(t, rung.Close, OutcomeUpFailed, err)
	}
	return rung, OutcomeServing, nil
}

// wireGuardOpener opens one virtual TCP connection to the host per forwarded
// local connection, mirroring exactly what the libp2p floor's opener does with
// libp2p streams.
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

// listenerAcceptor adapts a virtual TCP listener to Acceptor. The context is
// ignored because a netstack listener has no context-aware Accept; closing it is
// what unblocks the call, which is exactly what the rung's teardown does.
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
