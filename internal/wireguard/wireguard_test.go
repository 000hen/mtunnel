package wireguard

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"mtunnel-libp2p/internal/transport"
)

// keypair generates one side's static identity the same way internal/tunnel does, so
// these tests exercise the stdlib-X25519-to-WireGuard key compatibility the tier
// depends on rather than a test-only shortcut.
func keypair(t *testing.T) (private, public [32]byte) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate X25519 key: %v", err)
	}
	copy(private[:], key.Bytes())
	copy(public[:], key.PublicKey().Bytes())
	return private, public
}

// pairedConn presents an unconnected UDP socket as the connected net.Conn Bind
// expects, which is what a punched ICE connection looks like from here: message
// boundaries preserved, one reachable peer, working deadlines.
type pairedConn struct {
	*net.UDPConn
	remote *net.UDPAddr
}

func (c pairedConn) Read(p []byte) (int, error) {
	for {
		n, addr, err := c.UDPConn.ReadFromUDP(p)
		if err != nil {
			return n, err
		}
		// Loopback sockets are reachable by anything on the machine; a real punched
		// path is not, so ignore strays rather than feed them to the device.
		if addr.Port != c.remote.Port {
			continue
		}
		return n, nil
	}
}

func (c pairedConn) Write(p []byte) (int, error) { return c.UDPConn.WriteToUDP(p, c.remote) }
func (c pairedConn) RemoteAddr() net.Addr        { return c.remote }

var _ net.Conn = pairedConn{}

// substratePair returns two connected loopback UDP conns, closed when the test ends.
func substratePair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()

	listen := func() *net.UDPConn {
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatalf("listen UDP: %v", err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}

	a, b := listen(), listen()
	return pairedConn{UDPConn: a, remote: b.LocalAddr().(*net.UDPAddr)},
		pairedConn{UDPConn: b, remote: a.LocalAddr().(*net.UDPAddr)}
}

// tunnelPair builds both ends of a tier: two devices that trust each other's keys,
// wired through a real UDP substrate. It returns them with the host first.
func tunnelPair(t *testing.T) (*Tunnel, *Tunnel) {
	t.Helper()

	hostPriv, hostPub := keypair(t)
	clientPriv, clientPub := keypair(t)
	hostSubstrate, clientSubstrate := substratePair(t)

	host, err := New(hostSubstrate, Config{
		PrivateKey:    hostPriv,
		PeerPublicKey: clientPub,
		Local:         HostAddr,
		Peer:          ClientAddr,
	})
	if err != nil {
		t.Fatalf("build host device: %v", err)
	}
	t.Cleanup(func() { _ = host.Close() })

	client, err := New(clientSubstrate, Config{
		PrivateKey:    clientPriv,
		PeerPublicKey: hostPub,
		Local:         ClientAddr,
		Peer:          HostAddr,
		Initiate:      true,
	})
	if err != nil {
		t.Fatalf("build client device: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	return host, client
}

// TestTunnelRoundTrip is the tier's end-to-end proof: two devices handshake over a
// real socket and carry a virtual TCP connection between them, which is exactly the
// path a forwarded connection takes.
func TestTunnelRoundTrip(t *testing.T) {
	t.Parallel()
	host, client := tunnelPair(t)

	// Listen before Up on the host side, the same ordering serveWireGuardHost uses:
	// the client dials the moment its handshake lands, and a listener that does not
	// exist yet answers with a reset.
	ln, err := host.ListenTCP(netip.AddrPortFrom(HostAddr, VirtualPort))
	if err != nil {
		t.Fatalf("listen on the virtual address: %v", err)
	}
	defer ln.Close()

	if err := host.Up(); err != nil {
		t.Fatalf("host Up: %v", err)
	}
	if err := client.Up(); err != nil {
		t.Fatalf("client Up: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	start := time.Now()
	if err := client.WaitHandshake(ctx, 15*time.Second); err != nil {
		t.Fatalf("wait for handshake: %v", err)
	}
	// Noise-IK is one round trip over a socket with no network in between, so this
	// lands in milliseconds when it lands at all. The bound is here to catch the way
	// it silently stops doing that: if both sides initiate at once they cancel each
	// other out and only wireguard-go's 5s retransmit recovers, which a test with a
	// 15s budget would otherwise pass without complaint.
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("handshake took %v; a 1-RTT exchange this slow means it was retransmitted, not negotiated", elapsed)
	}

	// Echo one connection, mirroring what the host does with a forwarded service.
	served := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			served <- err
			return
		}
		defer c.Close()
		_, err = io.Copy(c, c)
		served <- err
	}()

	c, err := client.DialTCP(ctx, netip.AddrPortFrom(HostAddr, VirtualPort))
	if err != nil {
		t.Fatalf("dial through the tunnel: %v", err)
	}
	defer c.Close()

	payload := []byte("forwarded through a punched wireguard device")
	if _, err := c.Write(payload); err != nil {
		t.Fatalf("write through the tunnel: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read through the tunnel: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("round-tripped %q, want %q", got, payload)
	}

	// Closing the client end ends the echo, which is how the handler learns a
	// forwarded connection is done.
	_ = c.Close()
	select {
	case err := <-served:
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			t.Errorf("echo handler: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Error("echo handler did not finish after the client closed")
	}
}

// TestTunnelUDPRoundTrip is the forwarded-UDP path end to end: two devices handshake,
// each builds its multiplexer over the single virtual UDP conn, and several flows run
// concurrently without touching each other.
//
// It is the UDP counterpart of TestTunnelRoundTrip and covers what that one cannot -
// the sub-mode where message boundaries are the contract, not a byte stream.
func TestTunnelUDPRoundTrip(t *testing.T) {
	t.Parallel()
	host, client := tunnelPair(t)

	if err := host.Up(); err != nil {
		t.Fatalf("host Up: %v", err)
	}
	if err := client.Up(); err != nil {
		t.Fatalf("client Up: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := client.WaitHandshake(ctx, 15*time.Second); err != nil {
		t.Fatalf("wait for handshake: %v", err)
	}

	hostMux, err := host.NewUDPMux(HostAddr, ClientAddr, false)
	if err != nil {
		t.Fatalf("host UDP mux: %v", err)
	}
	defer hostMux.Close()

	clientMux, err := client.NewUDPMux(ClientAddr, HostAddr, true)
	if err != nil {
		t.Fatalf("client UDP mux: %v", err)
	}
	defer clientMux.Close()

	// Echo every flow the client starts, mirroring what the host does with a forwarded
	// UDP service.
	go func() {
		for {
			s, err := hostMux.AcceptStream(ctx)
			if err != nil {
				return
			}
			go func() {
				defer s.Close()
				buf := make([]byte, 2048)
				for {
					n, err := s.Read(buf)
					if err != nil {
						return
					}
					if _, err := s.Write(append([]byte("echo:"), buf[:n]...)); err != nil {
						return
					}
				}
			}()
		}
	}()

	const flows = 3
	streams := make([]transport.Stream, flows)
	for i := range streams {
		s, err := clientMux.OpenStream(ctx)
		if err != nil {
			t.Fatalf("open flow %d: %v", i, err)
		}
		defer s.Close()
		streams[i] = s
	}

	// Interleave writes across flows before reading any reply, so a mux that merely
	// preserved order rather than routing by ID could not pass.
	buf := make([]byte, 2048)
	for round := range 2 {
		for i, s := range streams {
			if _, err := s.Write([]byte{byte('0' + i), byte('a' + round)}); err != nil {
				t.Fatalf("flow %d write: %v", i, err)
			}
		}
		for i, s := range streams {
			n, err := s.Read(buf)
			if err != nil {
				t.Fatalf("flow %d read: %v", i, err)
			}
			want := string([]byte{'e', 'c', 'h', 'o', ':', byte('0' + i), byte('a' + round)})
			if got := string(buf[:n]); got != want {
				t.Fatalf("flow %d round %d: got %q, want %q", i, round, got, want)
			}
		}
	}

	// One write is one message: a 1200-byte payload comes back whole, not spliced with
	// its neighbours or split across reads. internal/udp's length framing rides inside
	// these bytes and would frame the wrong payload otherwise.
	large := bytes.Repeat([]byte("m"), 1200)
	if _, err := streams[0].Write(large); err != nil {
		t.Fatalf("write large: %v", err)
	}
	n, err := streams[0].Read(buf)
	if err != nil {
		t.Fatalf("read large: %v", err)
	}
	if want := append([]byte("echo:"), large...); !bytes.Equal(buf[:n], want) {
		t.Errorf("large datagram round-tripped %d bytes, want %d", n, len(want))
	}
}

// TestTunnelUDPMuxCloseUnblocksReaders proves the teardown path: closing the mux ends
// its receive loop and releases anything parked on a flow, which is what stops the
// host's forward goroutines from outliving the tier.
func TestTunnelUDPMuxCloseUnblocksReaders(t *testing.T) {
	t.Parallel()
	host, _ := tunnelPair(t)

	if err := host.Up(); err != nil {
		t.Fatalf("host Up: %v", err)
	}
	mux, err := host.NewUDPMux(HostAddr, ClientAddr, false)
	if err != nil {
		t.Fatalf("UDP mux: %v", err)
	}

	accepting := make(chan error, 1)
	go func() {
		_, err := mux.AcceptStream(context.Background())
		accepting <- err
	}()

	time.Sleep(50 * time.Millisecond)
	if err := mux.Close(); err != nil {
		t.Fatalf("close mux: %v", err)
	}

	select {
	case err := <-accepting:
		if err == nil {
			t.Error("AcceptStream returned a flow after Close")
		}
	case <-time.After(10 * time.Second):
		t.Error("AcceptStream never returned after Close")
	}

	// Closing twice must be harmless: teardown reaches it from more than one path.
	if err := mux.Close(); err != nil {
		t.Errorf("second close: %v", err)
	}
}

// TestTunnelCloseLeavesSubstrateOpen pins the ownership decision the tier's teardown
// depends on: internal/nat's agent owns the punched conn, so a device that closed it
// would leave two owners and a double close.
func TestTunnelCloseLeavesSubstrateOpen(t *testing.T) {
	t.Parallel()
	priv, pub := keypair(t)
	substrate, peer := substratePair(t)

	tun, err := New(substrate, Config{
		PrivateKey:    priv,
		PeerPublicKey: pub,
		Local:         ClientAddr,
		Peer:          HostAddr,
	})
	if err != nil {
		t.Fatalf("build device: %v", err)
	}
	if err := tun.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}
	if err := tun.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Close is called on every teardown path, sometimes more than once as composed
	// closers unwind, so it has to stay safe to repeat.
	if err := tun.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	if _, err := substrate.Write([]byte("still usable")); err != nil {
		t.Fatalf("substrate unusable after the device closed: %v", err)
	}
	buf := make([]byte, 64)
	if err := peer.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	n, err := peer.Read(buf)
	if err != nil {
		t.Fatalf("read from the substrate after the device closed: %v", err)
	}
	if string(buf[:n]) != "still usable" {
		t.Errorf("substrate delivered %q, want %q", buf[:n], "still usable")
	}
}

// TestNewRejectsMissingPeerKey covers the token-compatibility path: a token that
// predates WireGuard support decodes to an all-zero key, and building a device that
// encrypts to nobody would fail later and less clearly.
func TestNewRejectsMissingPeerKey(t *testing.T) {
	t.Parallel()
	priv, _ := keypair(t)
	substrate, _ := substratePair(t)

	tun, err := New(substrate, Config{
		PrivateKey: priv,
		Local:      ClientAddr,
		Peer:       HostAddr,
	})
	if !errors.Is(err, ErrNoPeerKey) {
		t.Fatalf("New with a zero peer key = %v, want %v", err, ErrNoPeerKey)
	}
	if tun != nil {
		t.Error("New returned a tunnel alongside an error")
	}
}

// TestWaitHandshakeTimeout is the fallback trigger: a peer that never answers has to
// surface as a bounded failure so the ladder can drop to the next tier, not as a
// tunnel that hangs.
func TestWaitHandshakeTimeout(t *testing.T) {
	t.Parallel()
	priv, pub := keypair(t)
	// A substrate whose peer socket exists but has no device behind it: packets go
	// somewhere and nothing ever answers.
	substrate, _ := substratePair(t)

	tun, err := New(substrate, Config{
		PrivateKey:    priv,
		PeerPublicKey: pub,
		Local:         ClientAddr,
		Peer:          HostAddr,
		Initiate:      true,
	})
	if err != nil {
		t.Fatalf("build device: %v", err)
	}
	defer tun.Close()

	if err := tun.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}

	start := time.Now()
	err = tun.WaitHandshake(context.Background(), 300*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitHandshake error = %v, want it to wrap %v", err, context.DeadlineExceeded)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("WaitHandshake took %v to honour a 300ms timeout", elapsed)
	}
}

// TestWaitHandshakeHonoursContext covers the other way the wait ends: the session is
// being torn down, so the timeout is irrelevant and the wait must return anyway.
func TestWaitHandshakeHonoursContext(t *testing.T) {
	t.Parallel()
	priv, pub := keypair(t)
	substrate, _ := substratePair(t)

	tun, err := New(substrate, Config{
		PrivateKey:    priv,
		PeerPublicKey: pub,
		Local:         ClientAddr,
		Peer:          HostAddr,
	})
	if err != nil {
		t.Fatalf("build device: %v", err)
	}
	defer tun.Close()

	if err := tun.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err = tun.WaitHandshake(ctx, time.Hour)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("WaitHandshake error = %v, want it to wrap %v", err, context.Canceled)
	}
	if elapsed := time.Since(start); elapsed > 30*time.Second {
		t.Errorf("WaitHandshake ignored cancellation for %v", elapsed)
	}
}

// TestIpcConfigShape guards the two lines that are easy to get wrong and fail late:
// set= belongs to the UAPI socket protocol and IpcSet rejects it, and listen_port is
// meaningless to a bind that ignores ports.
//
// It also pins the keepalive to the initiator. That line is what makes device.Up
// speak, so rendering it on both sides is what caused two peers coming up together
// to collide and lose five seconds to a retransmit.
func TestIpcConfigShape(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		initiate bool
		local    netip.Addr
		peer     netip.Addr
		want     []string
		unwanted []string
	}{
		{
			name:     "initiator",
			initiate: true,
			local:    ClientAddr,
			peer:     HostAddr,
			want: []string{
				"allowed_ip=10.64.0.1/32\n",
				"persistent_keepalive_interval=25\n",
			},
		},
		{
			name:  "responder",
			local: HostAddr,
			peer:  ClientAddr,
			want:  []string{"allowed_ip=10.64.0.2/32\n"},
			// Silence until spoken to is the whole point: a responder that sends a
			// keepalive on Up is a responder that initiates.
			unwanted: []string{"persistent_keepalive_interval="},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := Config{
				PrivateKey:    [32]byte{1},
				PeerPublicKey: [32]byte{2},
				Local:         tt.local,
				Peer:          tt.peer,
				Initiate:      tt.initiate,
			}
			got := ipcConfig(cfg, NewBind(newFakeConn()))

			want := append([]string{
				"private_key=0100000000000000000000000000000000000000000000000000000000000000\n",
				"public_key=0200000000000000000000000000000000000000000000000000000000000000\n",
				"endpoint=127.0.0.1:51820\n",
			}, tt.want...)
			for _, line := range want {
				if !strings.Contains(got, line) {
					t.Errorf("ipcConfig missing %q; got:\n%s", line, got)
				}
			}
			for _, line := range append([]string{"set=", "listen_port="}, tt.unwanted...) {
				if strings.Contains(got, line) {
					t.Errorf("ipcConfig contains %q, which IpcSet rejects or ignores; got:\n%s", line, got)
				}
			}

			// The real check that the shape is right: the device parser accepts it.
			substrate, _ := substratePair(t)
			if _, err := New(substrate, cfg); err != nil {
				t.Fatalf("IpcSet rejected the rendered config: %v", err)
			}
		})
	}
}
