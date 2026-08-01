// Package wireguard carries tunnel traffic over a WireGuard device built on a
// punched substrate, replacing libp2p in the data path.
//
// It is a leaf package in the same sense as internal/transport and internal/nat: the
// standard library and wireguard-go, never libp2p. The substrate it is handed is an
// ordinary net.Conn, so nothing here knows or cares that a libp2p stream was used to
// negotiate it.
//
// The device is entirely userspace. wireguard-go's netstack TUN puts a gVisor IP
// stack behind the encrypted link, so the host listens and the client dials on
// virtual addresses that exist only inside the process - no OS network interface, no
// privileges, nothing to clean up if the process dies.
package wireguard

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"mtunnel-libp2p/internal/flowmux"
)

const (
	// MTU leaves room inside a 1500-byte path for WireGuard's own framing (32 bytes
	// of data-packet overhead) plus the UDP/IP headers underneath it. 1420 is the
	// value wg-quick picks for the same reason.
	MTU = 1420

	// VirtualPort is the port the host's virtual listener uses. It is arbitrary -
	// nothing outside the two devices can reach this address space - but it must be
	// the same constant on both sides, so it is fixed here rather than negotiated.
	VirtualPort = 51820

	// keepaliveSeconds is what makes device.Up send a packet at all: wireguard-go
	// initiates its handshake from that first keepalive, so a peer configured without
	// one stays idle until application traffic arrives. It also refreshes the NAT
	// mapping the punch created, which would otherwise expire in well under a minute
	// of silence.
	//
	// Only the initiator is configured with it - see Config.Initiate.
	keepaliveSeconds = 25

	// handshakePollInterval is how often WaitHandshake re-reads the device state.
	// The handshake itself completes in about a millisecond over a working path, so
	// this bounds how long the common case is left waiting on a timer.
	handshakePollInterval = 25 * time.Millisecond

	// maxVirtualDatagram bounds one read from the virtual UDP conn. 65535 is what an
	// IPv4 datagram's length field can express, so nothing larger can arrive and no
	// read is ever truncated. Datagrams past the device MTU are fragmented and
	// reassembled by the virtual IP stack, invisibly to this package.
	maxVirtualDatagram = 65535
)

// HostAddr and ClientAddr are the two virtual addresses inside the tunnel. They are
// fixed rather than negotiated because only these two devices share the address
// space, and they cannot collide with anything on the real network: netstack routes
// them entirely in-process.
var (
	HostAddr   = netip.MustParseAddr("10.64.0.1")
	ClientAddr = netip.MustParseAddr("10.64.0.2")
)

// ErrNoPeerKey reports that the peer advertised no WireGuard public key, which makes
// the tier impossible: there is nothing to encrypt to.
var ErrNoPeerKey = errors.New("wireguard: peer advertised no public key")

// Config is one side's device configuration. Both sides fill it in symmetrically,
// swapping Local and Peer.
type Config struct {
	// PrivateKey is this side's static X25519 key, generated fresh per run.
	PrivateKey [32]byte
	// PeerPublicKey is the key the peer advertised over the negotiate stream.
	PeerPublicKey [32]byte

	// Local and Peer are the virtual addresses of the two devices.
	Local netip.Addr
	Peer  netip.Addr

	// Initiate makes this side open the Noise handshake when it comes up. Exactly
	// one side must set it, and it is the client, matching who initiates everywhere
	// else in this binary.
	//
	// Both sides initiating is not merely redundant, it is actively worse than one:
	// WireGuard is not a symmetric protocol, and two peers that initiate within the
	// same millisecond - which is what happens here, because both come up the instant
	// a punch they ran together completes - each overwrite their own pending
	// handshake while responding to the other's. Both then reject the response they
	// asked for ("Received invalid response message") and the tier stalls until
	// wireguard-go's 5s retransmit breaks the tie, which is most of the handshake
	// budget spent on an entirely self-inflicted collision.
	Initiate bool

	// Diagnostic gates wireguard-go's verbose logging, matching the flag of the same
	// name elsewhere in the binary. Device errors are reported either way.
	Diagnostic bool
}

// A Tunnel is one WireGuard device and the virtual network behind it.
type Tunnel struct {
	dev  *device.Device
	tnet *netstack.Net

	closeOnce sync.Once
}

// New builds a configured, not-yet-running device over substrate.
//
// It does not take ownership of substrate: the ICE agent that produced it is what
// releases it, and Close deliberately leaves it alone so there is exactly one owner.
// Callers must close the substrate themselves after Close returns.
func New(substrate net.Conn, cfg Config) (*Tunnel, error) {
	if cfg.PeerPublicKey == ([32]byte{}) {
		return nil, ErrNoPeerKey
	}

	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{cfg.Local}, nil, MTU)
	if err != nil {
		return nil, fmt.Errorf("create netstack TUN: %w", err)
	}

	bind := NewBind(substrate)
	dev := device.NewDevice(tunDev, bind, newLogger(cfg.Diagnostic))
	if err := dev.IpcSet(ipcConfig(cfg, bind)); err != nil {
		dev.Close()
		return nil, fmt.Errorf("configure WireGuard device: %w", err)
	}

	return &Tunnel{dev: dev, tnet: tnet}, nil
}

// Up starts the device. On the initiator that also sends the first handshake
// initiation; the responder simply becomes ready to answer one. Bring the host's
// listener up before calling this: a client whose handshake completes dials
// immediately, and a listener that does not exist yet answers with a reset.
func (t *Tunnel) Up() error {
	if err := t.dev.Up(); err != nil {
		return fmt.Errorf("bring WireGuard device up: %w", err)
	}
	return nil
}

// WaitHandshake blocks until the peer has completed a Noise handshake, ctx is done,
// or timeout expires.
//
// This is the tier's readiness signal. Probing with a real virtual connection would
// prove more, but it would also mean opening - and having the host serve - a
// connection to the forwarded service purely as a health check.
func (t *Tunnel) WaitHandshake(ctx context.Context, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(handshakePollInterval)
	defer ticker.Stop()

	for {
		done, err := t.handshaken()
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return fmt.Errorf("wait for WireGuard handshake: %w", ctx.Err())
		}
	}
}

// handshaken reports whether a peer has recorded a completed handshake. wireguard-go
// exposes no direct "the tunnel is up" signal, so this reads the UAPI state dump:
// last_handshake_time_sec is the one field that separates negotiated keys from a
// device still retrying.
func (t *Tunnel) handshaken() (bool, error) {
	state, err := t.dev.IpcGet()
	if err != nil {
		return false, fmt.Errorf("read WireGuard device state: %w", err)
	}
	for line := range strings.SplitSeq(state, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || key != "last_handshake_time_sec" {
			continue
		}
		if value != "" && value != "0" {
			return true, nil
		}
	}
	return false, nil
}

// ListenTCP opens a virtual TCP listener, the tunnel-side equivalent of the libp2p
// stream handler the host registers today.
func (t *Tunnel) ListenTCP(addr netip.AddrPort) (net.Listener, error) {
	ln, err := t.tnet.ListenTCPAddrPort(addr)
	if err != nil {
		return nil, fmt.Errorf("listen on virtual %s: %w", addr, err)
	}
	return ln, nil
}

// DialTCP opens one virtual TCP connection, the tunnel-side equivalent of opening a
// libp2p stream.
func (t *Tunnel) DialTCP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	c, err := t.tnet.DialContextTCPAddrPort(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("dial virtual %s: %w", addr, err)
	}
	return c, nil
}

// NewUDPMux opens the one virtual UDP conn that carries every forwarded UDP flow, and
// multiplexes flows over it.
//
// Forwarded UDP is deliberately shaped differently from forwarded TCP here. TCP gets a
// virtual listener and one virtual connection per forwarded connection, because that
// is what netstack's TCP stack is for. UDP gets a single conn plus internal/flowmux,
// for two reasons:
//
//   - A virtual UDP listener is unconnected, so the host would have to demultiplex
//     client source ports itself and invent its own end-of-flow signal, UDP having no
//     close. flowmux's explicit FIN replaces that with something deterministic.
//   - It is the identical scheme the QUIC datagram tier runs, so both unreliable tiers
//     share one implementation rather than two that drift apart.
//
// Both sides bind a fixed virtual port and connect to the other's. Nothing else exists
// in this address space, so there is no ambiguity and no port to negotiate. dialing
// must be true on exactly one side - the client, matching who initiates everywhere
// else - so the two ends allocate flow IDs from disjoint namespaces.
func (t *Tunnel) NewUDPMux(local, peer netip.Addr, dialing bool) (*UDPMux, error) {
	conn, err := t.tnet.DialUDPAddrPort(
		netip.AddrPortFrom(local, VirtualPort),
		netip.AddrPortFrom(peer, VirtualPort),
	)
	if err != nil {
		return nil, fmt.Errorf("open virtual UDP conn %s -> %s: %w", local, peer, err)
	}

	m := &UDPMux{conn: conn}
	m.Mux = flowmux.New(flowmux.Config{
		Send:    m.send,
		Recv:    m.recv,
		Dialing: dialing,
		OnDrop:  m.logDrop,
	})
	return m, nil
}

// UDPMux is the flow multiplexer for forwarded UDP, plus the virtual conn it runs on.
type UDPMux struct {
	*flowmux.Mux

	conn      net.Conn
	closeOnce sync.Once
}

func (m *UDPMux) send(msg []byte) error {
	_, err := m.conn.Write(msg)
	return err
}

// recv returns one whole datagram. The buffer is sized past anything the virtual
// stack can deliver, so a message is never truncated - which matters because these
// bytes carry internal/udp's own length framing, and a short read would frame the
// wrong payload rather than merely lose the tail.
//
// A fresh buffer per call is what lets the mux take ownership of the slice, as its
// contract requires.
func (m *UDPMux) recv() ([]byte, error) {
	buf := make([]byte, maxVirtualDatagram)
	n, err := m.conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (m *UDPMux) logDrop(id uint32, reason string) {
	slog.Warn("tunnel_wireguard_flow_dropped", "flow", id, "reason", reason)
}

// Close ends every flow and closes the virtual conn, which is what unblocks the mux's
// receive loop. The device and the substrate underneath are not touched: Tunnel.Close
// owns the first and the ICE agent owns the second.
func (m *UDPMux) Close() error {
	var err error
	m.closeOnce.Do(func() {
		_ = m.Mux.Close()
		err = m.conn.Close()
	})
	return err
}

// Close shuts the device down and unblocks everything riding on it. It does not
// close the substrate - see New.
func (t *Tunnel) Close() error {
	t.closeOnce.Do(t.dev.Close)
	return nil
}

// ipcConfig renders the UAPI text form IpcSet expects. Interface-level keys come
// first, then one block per peer.
//
// Two lines that look like they belong here do not. listen_port is meaningless with
// a connected substrate, whose Bind ignores the port entirely. And set=1 belongs to
// the UAPI *socket* protocol handled by IpcHandle, which strips it before
// delegating; IpcSet feeds the string straight to the parser, which rejects it as an
// invalid device key.
//
// The responder omits persistent_keepalive_interval, which is what keeps it quiet
// until the initiator speaks (see Config.Initiate). It is not left without a way to
// hold the path open: wireguard-go answers received data with a keepalive of its own
// after ten idle seconds, and the ICE agent underneath runs its own consent checks
// regardless of what WireGuard does.
func ipcConfig(cfg Config, bind *Bind) string {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(cfg.PrivateKey[:]))
	fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(cfg.PeerPublicKey[:]))
	fmt.Fprintf(&b, "allowed_ip=%s/%d\n", cfg.Peer, cfg.Peer.BitLen())
	// The endpoint value is resolved by Bind.ParseEndpoint, which ignores it; naming
	// the substrate's real peer keeps the device's own logging honest.
	fmt.Fprintf(&b, "endpoint=%s\n", bind.Endpoint().DstToString())
	if cfg.Initiate {
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", keepaliveSeconds)
	}
	return b.String()
}

// newLogger adapts device.Logger - two Printf-style function fields - onto slog, the
// same shape internal/nat uses for pion's logger.
//
// Verbose output is gated behind -diagnostic because wireguard-go narrates every
// handshake and keepalive. Errors are not: they are rare, and a device that cannot
// send is exactly what someone debugging a dead tunnel needs to see.
func newLogger(diagnostic bool) *device.Logger {
	verbose := func(string, ...any) {}
	if diagnostic {
		verbose = func(format string, args ...any) {
			slog.Debug("tunnel_wireguard", "message", fmt.Sprintf(format, args...))
		}
	}
	return &device.Logger{
		Verbosef: verbose,
		Errorf: func(format string, args ...any) {
			slog.Warn("tunnel_wireguard", "message", fmt.Sprintf(format, args...))
		},
	}
}
