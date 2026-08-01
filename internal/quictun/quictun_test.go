package quictun

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

const testTimeout = 20 * time.Second

// udpLink presents one end of a real loopback UDP socket pair as a net.Conn.
//
// The tests deliberately use actual sockets rather than an in-memory fake. The whole
// package is written against the awkward parts of a punched substrate - message
// boundaries, working read deadlines, one fixed peer - and a fake would be free to be
// more accommodating than the real thing on exactly those points.
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

func udpPair(t *testing.T) (net.Conn, net.Conn) {
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

type pair struct {
	client, host       *Tunnel
	clientSub, hostSub net.Conn
}

// establish brings up both ends of a tunnel over a fresh socket pair.
func establish(t *testing.T, datagrams bool) pair {
	t.Helper()

	clientID, err := NewIdentity()
	if err != nil {
		t.Fatalf("client identity: %v", err)
	}
	hostID, err := NewIdentity()
	if err != nil {
		t.Fatalf("host identity: %v", err)
	}

	clientSub, hostSub := udpPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	type result struct {
		tunnel *Tunnel
		err    error
	}
	accepted := make(chan result, 1)
	go func() {
		tunnel, err := Accept(ctx, hostSub, Config{
			Identity:        hostID,
			PeerFingerprint: clientID.Fingerprint,
			Datagrams:       datagrams,
		})
		accepted <- result{tunnel, err}
	}()

	client, err := Dial(ctx, clientSub, Config{
		Identity:        clientID,
		PeerFingerprint: hostID.Fingerprint,
		Datagrams:       datagrams,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	got := <-accepted
	if got.err != nil {
		t.Fatalf("accept: %v", got.err)
	}
	t.Cleanup(func() { _ = got.tunnel.Close() })

	return pair{client: client, host: got.tunnel, clientSub: clientSub, hostSub: hostSub}
}

func TestTunnelStreamRoundTrip(t *testing.T) {
	t.Parallel()

	p := establish(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	echoed := make(chan error, 1)
	go func() {
		s, err := p.host.AcceptStream(ctx)
		if err != nil {
			echoed <- err
			return
		}
		defer s.Close()
		// io.Copy runs until the peer half-closes, which is what proves CloseWrite
		// reaches the far end as a clean EOF rather than an abort.
		_, err = io.Copy(s, s)
		echoed <- err
	}()

	s, err := p.client.OpenStream(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	payload := bytes.Repeat([]byte("mtunnel-quic-stream."), 1000)
	if _, err := s.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	cw, ok := s.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("stream does not implement CloseWrite; the TCP forwarder probes for it")
	}
	if err := cw.CloseWrite(); err != nil {
		t.Fatalf("close write: %v", err)
	}

	got, err := io.ReadAll(s)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echoed %d bytes, want %d", len(got), len(payload))
	}
	if err := <-echoed; err != nil {
		t.Fatalf("host echo: %v", err)
	}
}

func TestTunnelStreamsAreIndependent(t *testing.T) {
	t.Parallel()

	p := establish(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	const streams = 4
	done := make(chan error, streams)
	go func() {
		for range streams {
			s, err := p.host.AcceptStream(ctx)
			if err != nil {
				done <- err
				return
			}
			go func() {
				defer s.Close()
				_, _ = io.Copy(s, s)
			}()
		}
	}()

	for i := range streams {
		s, err := p.client.OpenStream(ctx)
		if err != nil {
			t.Fatalf("open stream %d: %v", i, err)
		}
		go func() {
			defer s.Close()
			want := bytes.Repeat([]byte{byte('a' + i)}, 512)
			if _, err := s.Write(want); err != nil {
				done <- err
				return
			}
			s.(interface{ CloseWrite() error }).CloseWrite()
			got, err := io.ReadAll(s)
			if err != nil {
				done <- err
				return
			}
			if !bytes.Equal(got, want) {
				done <- errors.New("stream crossed with another")
				return
			}
			done <- nil
		}()
	}

	for range streams {
		if err := <-done; err != nil {
			t.Fatalf("stream: %v", err)
		}
	}
}

func TestTunnelDatagramFlowRoundTrip(t *testing.T) {
	t.Parallel()

	p := establish(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	served := make(chan error, 1)
	go func() {
		s, err := p.host.AcceptStream(ctx)
		if err != nil {
			served <- err
			return
		}
		defer s.Close()
		buf := make([]byte, 2048)
		for range 3 {
			n, err := s.Read(buf)
			if err != nil {
				served <- err
				return
			}
			if _, err := s.Write(buf[:n]); err != nil {
				served <- err
				return
			}
		}
		served <- nil
	}()

	s, err := p.client.OpenStream(ctx)
	if err != nil {
		t.Fatalf("open flow: %v", err)
	}
	defer s.Close()

	buf := make([]byte, 2048)
	for i := range 3 {
		want := bytes.Repeat([]byte{byte('A' + i)}, 200+i)
		if _, err := s.Write(want); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		n, err := s.Read(buf)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		// One write is one datagram, so a read returns exactly that message - never
		// two spliced together and never a fragment of the next.
		if !bytes.Equal(buf[:n], want) {
			t.Fatalf("datagram %d: got %d bytes, want %d", i, n, len(want))
		}
	}
	if err := <-served; err != nil {
		t.Fatalf("host: %v", err)
	}
}

// Flows share one datagram channel, so the demultiplexer is the only thing keeping
// them apart. This is the test that would catch it dropping the flow header or
// mixing IDs.
func TestTunnelDatagramFlowsAreIndependent(t *testing.T) {
	t.Parallel()

	p := establish(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	const flows = 5
	go func() {
		for range flows {
			s, err := p.host.AcceptStream(ctx)
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
					// Echo with a marker so a reply routed to the wrong flow is
					// visible rather than merely plausible.
					if _, err := s.Write(append([]byte("echo:"), buf[:n]...)); err != nil {
						return
					}
				}
			}()
		}
	}()

	opened := make([]interface {
		Read([]byte) (int, error)
		Write([]byte) (int, error)
		Close() error
	}, 0, flows)
	for i := range flows {
		s, err := p.client.OpenStream(ctx)
		if err != nil {
			t.Fatalf("open flow %d: %v", i, err)
		}
		defer s.Close()
		opened = append(opened, s)
	}

	// Interleave writes across every flow before reading any reply, so a
	// demultiplexer that merely happens to preserve order cannot pass.
	for round := range 3 {
		for i, s := range opened {
			if _, err := s.Write([]byte{byte('0' + i), byte('a' + round)}); err != nil {
				t.Fatalf("flow %d write: %v", i, err)
			}
		}
		for i, s := range opened {
			buf := make([]byte, 64)
			n, err := s.Read(buf)
			if err != nil {
				t.Fatalf("flow %d read: %v", i, err)
			}
			want := []byte{'e', 'c', 'h', 'o', ':', byte('0' + i), byte('a' + round)}
			if !bytes.Equal(buf[:n], want) {
				t.Fatalf("flow %d round %d: got %q, want %q", i, round, buf[:n], want)
			}
		}
	}
}

// Closing a flow must reach the peer promptly. Without the FIN the host end would
// linger until something else noticed, holding a forwarded local connection open.
func TestTunnelDatagramFlowCloseReachesPeer(t *testing.T) {
	t.Parallel()

	p := establish(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	ended := make(chan error, 1)
	go func() {
		s, err := p.host.AcceptStream(ctx)
		if err != nil {
			ended <- err
			return
		}
		buf := make([]byte, 2048)
		if _, err := s.Read(buf); err != nil {
			ended <- err
			return
		}
		_, err = s.Read(buf)
		ended <- err
	}()

	s, err := p.client.OpenStream(ctx)
	if err != nil {
		t.Fatalf("open flow: %v", err)
	}
	if _, err := s.Write([]byte("open the flow")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	select {
	case err := <-ended:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("host read after peer close = %v, want io.EOF", err)
		}
	case <-ctx.Done():
		t.Fatal("host never observed the flow closing")
	}
}

// The pin is the QUIC tier's entire trust model, so a mismatch has to be fatal rather
// than merely logged. InsecureSkipVerify is set on both configs; if the callback were
// wrong this test is what notices that it now accepts anything.
func TestTunnelRejectsMismatchedFingerprint(t *testing.T) {
	t.Parallel()

	clientID, err := NewIdentity()
	if err != nil {
		t.Fatalf("client identity: %v", err)
	}
	hostID, err := NewIdentity()
	if err != nil {
		t.Fatalf("host identity: %v", err)
	}
	impostor, err := NewIdentity()
	if err != nil {
		t.Fatalf("impostor identity: %v", err)
	}

	clientSub, hostSub := udpPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	// A rejected handshake never completes, so the host end can only give up on its
	// timeout. Shorten it rather than spend the production default on a test.
	const rejectTimeout = 1500 * time.Millisecond

	accepted := make(chan error, 1)
	go func() {
		tunnel, err := Accept(ctx, hostSub, Config{
			Identity:         hostID,
			PeerFingerprint:  clientID.Fingerprint,
			HandshakeTimeout: rejectTimeout,
		})
		if tunnel != nil {
			_ = tunnel.Close()
		}
		accepted <- err
	}()

	// The client pins a certificate the host does not hold.
	tunnel, err := Dial(ctx, clientSub, Config{
		Identity:         clientID,
		PeerFingerprint:  impostor.Fingerprint,
		HandshakeTimeout: rejectTimeout,
	})
	if err == nil {
		_ = tunnel.Close()
		t.Fatal("dial succeeded against an unpinned certificate")
	}
	if e := <-accepted; e == nil {
		t.Fatal("accept succeeded even though the client rejected the handshake")
	}
}

func TestTunnelRequiresPeerFingerprint(t *testing.T) {
	t.Parallel()

	id, err := NewIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	clientSub, _ := udpPair(t)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	// An all-zero fingerprint is what a peer that never sent one decodes to. It must
	// be refused by name rather than becoming an unmatchable pin.
	if _, err := Dial(ctx, clientSub, Config{Identity: id}); err == nil {
		t.Fatal("dial accepted a zero peer fingerprint")
	}
	if _, err := Dial(ctx, clientSub, Config{PeerFingerprint: id.Fingerprint}); err == nil {
		t.Fatal("dial accepted a missing local identity")
	}
}

// The cascade's defining constraint: a punch is expensive and one substrate has to
// survive a tier failing so the next rung can run on it. If closing the tunnel took
// the substrate with it, WireGuard failing would mean re-punching for QUIC.
func TestTunnelCloseLeavesSubstrateUsable(t *testing.T) {
	t.Parallel()

	p := establish(t, false)

	if err := p.client.Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}
	if err := p.host.Close(); err != nil {
		t.Fatalf("host close: %v", err)
	}

	// A second close must be harmless: teardown paths call it from more than one
	// place and the substrate is shared.
	if err := p.client.Close(); err != nil {
		t.Fatalf("second client close: %v", err)
	}

	const sentinel = "substrate still ours"
	if _, err := p.clientSub.Write([]byte(sentinel)); err != nil {
		t.Fatalf("write on the substrate after close: %v", err)
	}

	// CONNECTION_CLOSE frames from the teardown may still be in flight, so read past
	// them rather than assuming the sentinel is first.
	if err := p.hostSub.SetReadDeadline(time.Now().Add(testTimeout)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	buf := make([]byte, 2048)
	for {
		n, err := p.hostSub.Read(buf)
		if err != nil {
			t.Fatalf("read on the substrate after close: %v", err)
		}
		if string(buf[:n]) == sentinel {
			return
		}
	}
}

// Closing the tunnel must also release whatever is parked on an accept, or host-side
// shutdown would hang waiting for a peer that is never coming.
func TestTunnelCloseReleasesAccept(t *testing.T) {
	t.Parallel()

	for _, datagrams := range []bool{false, true} {
		name := "streams"
		if datagrams {
			name = "datagrams"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			p := establish(t, datagrams)
			blocked := make(chan error, 1)
			go func() {
				_, err := p.host.AcceptStream(context.Background())
				blocked <- err
			}()

			// Give the accept a moment to actually park before closing under it.
			time.Sleep(50 * time.Millisecond)
			if err := p.host.Close(); err != nil {
				t.Fatalf("close: %v", err)
			}

			select {
			case err := <-blocked:
				if err == nil {
					t.Fatal("AcceptStream returned a stream after Close")
				}
			case <-time.After(testTimeout):
				t.Fatal("AcceptStream never returned after Close")
			}
		})
	}
}
