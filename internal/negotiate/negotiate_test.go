package negotiate

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"io"
	"net"
	"reflect"
	"testing"
)

// connPair returns the two ends of a loopback TCP connection, closed automatically
// when the test finishes.
//
// net.Pipe is deliberately not used: it is unbuffered, so a write blocks until the
// far side reads. The handshake is symmetric - both sides send before either
// receives - which is correct over any buffered stream (a socket, a libp2p stream)
// but deadlocks instantly on an unbuffered pipe. A real socket reproduces production
// semantics; a pipe would only test an environment the code never runs in.
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

func TestSelectTier(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		local []Tier
		peer  []Tier
		want  Tier
	}{
		{
			name:  "both floor only",
			local: []Tier{TierLibp2p},
			peer:  []Tier{TierLibp2p},
			want:  TierLibp2p,
		},
		{
			name:  "shared wireguard preferred over quic",
			local: []Tier{TierWireGuard, TierQUIC, TierLibp2p},
			peer:  []Tier{TierWireGuard, TierQUIC, TierLibp2p},
			want:  TierWireGuard,
		},
		{
			name:  "only quic shared",
			local: []Tier{TierWireGuard, TierQUIC, TierLibp2p},
			peer:  []Tier{TierQUIC, TierLibp2p},
			want:  TierQUIC,
		},
		{
			name:  "incompatible non-libp2p tiers fall to floor",
			local: []Tier{TierWireGuard, TierLibp2p},
			peer:  []Tier{TierQUIC, TierLibp2p},
			want:  TierLibp2p,
		},
		{
			name:  "order in slice does not change cascade priority",
			local: []Tier{TierLibp2p, TierQUIC, TierWireGuard},
			peer:  []Tier{TierQUIC, TierLibp2p, TierWireGuard},
			want:  TierWireGuard,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := SelectTier(tt.local, tt.peer); got != tt.want {
				t.Errorf("SelectTier(%v, %v) = %q, want %q", tt.local, tt.peer, got, tt.want)
			}
		})
	}
}

func TestSharedCascade(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		local []Tier
		peer  []Tier
		want  []Tier
	}{
		{
			name:  "both floor only",
			local: []Tier{TierLibp2p},
			peer:  []Tier{TierLibp2p},
			want:  []Tier{TierLibp2p},
		},
		{
			name:  "everything shared gives the full ladder",
			local: []Tier{TierWireGuard, TierQUIC, TierLibp2p},
			peer:  []Tier{TierWireGuard, TierQUIC, TierLibp2p},
			want:  []Tier{TierWireGuard, TierQUIC, TierLibp2p},
		},
		{
			name:  "a tier only one side supports is not a rung",
			local: []Tier{TierWireGuard, TierQUIC, TierLibp2p},
			peer:  []Tier{TierQUIC, TierLibp2p},
			want:  []Tier{TierQUIC, TierLibp2p},
		},
		{
			name:  "incompatible forcing leaves only the floor",
			local: []Tier{TierWireGuard, TierLibp2p},
			peer:  []Tier{TierQUIC, TierLibp2p},
			want:  []Tier{TierLibp2p},
		},
		{
			name:  "slice order does not change cascade order",
			local: []Tier{TierLibp2p, TierQUIC, TierWireGuard},
			peer:  []Tier{TierQUIC, TierWireGuard, TierLibp2p},
			want:  []Tier{TierWireGuard, TierQUIC, TierLibp2p},
		},
		{
			// The floor is what both processes are already running, not a capability
			// either side can withdraw. A cascade that could run out of rungs would
			// turn an optional upgrade into a new way for a working tunnel to fail.
			name:  "the floor is appended even when nobody advertised it",
			local: []Tier{TierQUIC},
			peer:  []Tier{TierQUIC},
			want:  []Tier{TierQUIC, TierLibp2p},
		},
		{
			name:  "an unknown tier is not a rung",
			local: []Tier{Tier("carrier-pigeon"), TierLibp2p},
			peer:  []Tier{Tier("carrier-pigeon"), TierLibp2p},
			want:  []Tier{TierLibp2p},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := SharedCascade(tt.local, tt.peer)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SharedCascade(%v, %v) = %v, want %v", tt.local, tt.peer, got, tt.want)
			}
			// The whole scheme rests on both sides walking the identical ladder from
			// the identical pair of Hellos, with no extra round-trip to agree on it.
			if mirrored := SharedCascade(tt.peer, tt.local); !reflect.DeepEqual(mirrored, got) {
				t.Errorf("SharedCascade is not symmetric: %v from the other side, want %v", mirrored, got)
			}
			if head := SelectTier(tt.local, tt.peer); head != got[0] {
				t.Errorf("SelectTier = %q, want the cascade head %q", head, got[0])
			}
		})
	}
}

func TestEffectivePunchAttempts(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		local uint8
		peer  uint8
		want  uint8
	}{
		{
			// The case that keeps a mixed-version pairing working. gob decodes an absent
			// field as zero, so a peer built before PunchAttempts existed advertises 0 -
			// and 0 has to mean the one attempt that peer will actually make, not "no
			// attempts" and not "as many as I like".
			name:  "an absent peer field pins both sides to one attempt",
			local: 4,
			peer:  0,
			want:  1,
		},
		{
			name:  "an absent local field does the same",
			local: 0,
			peer:  4,
			want:  1,
		},
		{
			name:  "both absent is one attempt",
			local: 0,
			peer:  0,
			want:  1,
		},
		{
			name:  "agreement is taken at face value",
			local: 2,
			peer:  2,
			want:  2,
		},
		{
			// The lower number wins because a side that stopped punching would leave the
			// other waiting on an outcome swap it is never going to send.
			name:  "the more cautious side sets the limit",
			local: 5,
			peer:  2,
			want:  2,
		},
		{
			name:  "one is a legitimate request, not an absent field",
			local: 1,
			peer:  9,
			want:  1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := EffectivePunchAttempts(tt.local, tt.peer)
			if got != tt.want {
				t.Errorf("EffectivePunchAttempts(%d, %d) = %d, want %d", tt.local, tt.peer, got, tt.want)
			}
			// Both sides compute this from the same pair of Hellos and never compare
			// answers, so an asymmetric result would desynchronise the retry loop
			// silently - the failure it exists to prevent.
			if mirrored := EffectivePunchAttempts(tt.peer, tt.local); mirrored != got {
				t.Errorf("EffectivePunchAttempts is not symmetric: %d from the other side, want %d", mirrored, got)
			}
		})
	}
}

func TestExchangePunchOutcome(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		client     bool
		host       bool
		wantAgreed bool
	}{
		{name: "both landed", client: true, host: true, wantAgreed: true},
		{name: "neither landed", client: false, host: false, wantAgreed: false},
		{
			// The asymmetric cases are the reason this phase exists. One side's ICE can
			// finish while the other's context expires, and if the winner carried on
			// alone the two would be reading different message types off one stream.
			name: "client landed, host did not", client: true, host: false, wantAgreed: false,
		},
		{name: "host landed, client did not", client: false, host: true, wantAgreed: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			clientConn, hostConn := connPair(t)
			client := NewExchange(clientConn)
			host := NewExchange(hostConn)
			ctx := context.Background()

			type outcome struct {
				agreed bool
				err    error
			}
			hostDone := make(chan outcome, 1)
			go func() {
				agreed, err := host.ExchangePunchOutcome(ctx, tt.host)
				hostDone <- outcome{agreed, err}
			}()

			clientAgreed, err := client.ExchangePunchOutcome(ctx, tt.client)
			if err != nil {
				t.Fatalf("client ExchangePunchOutcome: %v", err)
			}
			got := <-hostDone
			if got.err != nil {
				t.Fatalf("host ExchangePunchOutcome: %v", got.err)
			}

			if clientAgreed != tt.wantAgreed {
				t.Errorf("client agreed = %v, want %v", clientAgreed, tt.wantAgreed)
			}
			// Both sides must reach the same verdict or the lockstep is a fiction.
			if got.agreed != clientAgreed {
				t.Errorf("host agreed = %v, client agreed = %v - the two sides disagree", got.agreed, clientAgreed)
			}
		})
	}
}

// The Attempt exchange is one-way, so it needs its own coverage: the symmetric swap
// tests would not catch a send and a receive that disagree about the message.
func TestExchangeAttempt(t *testing.T) {
	t.Parallel()

	clientConn, hostConn := connPair(t)
	client := NewExchange(clientConn)
	host := NewExchange(hostConn)
	ctx := context.Background()

	// The client walks the ladder and announces each rung as it reaches it, ending on
	// the floor when the punched substrate has nothing left to offer.
	sent := []Attempt{{Tier: TierWireGuard}, {Tier: TierQUIC}, {Tier: TierLibp2p}}
	errs := make(chan error, 1)
	go func() {
		for _, a := range sent {
			if err := client.SendAttempt(ctx, a); err != nil {
				errs <- err
				return
			}
		}
		errs <- nil
	}()

	for i, want := range sent {
		got, err := host.ReceiveAttempt(ctx)
		if err != nil {
			t.Fatalf("receive attempt %d: %v", i, err)
		}
		if got != want {
			t.Fatalf("attempt %d = %+v, want %+v", i, got, want)
		}
	}
	if err := <-errs; err != nil {
		t.Fatalf("send attempts: %v", err)
	}
}

func TestReceiveAttemptHonoursContext(t *testing.T) {
	t.Parallel()

	_, hostConn := connPair(t)
	host := NewExchange(hostConn)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// A peer that opens the stream and then goes quiet must not park the host forever.
	if _, err := host.ReceiveAttempt(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("ReceiveAttempt = %v, want context.Canceled", err)
	}
}

func TestHelloGobRoundTrip(t *testing.T) {
	t.Parallel()
	want := Hello{
		SupportedTiers:  []Tier{TierWireGuard, TierLibp2p},
		WireGuardPubKey: [32]byte{1, 2, 3, 30: 0xFF},
		PunchProbe:      true,
	}

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(want); err != nil {
		t.Fatalf("encode: %v", err)
	}
	var got Hello
	if err := gob.NewDecoder(&buf).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip mismatch: got %+v, want %+v", got, want)
	}
}

// TestHelloDecodesPeerWithoutPunchProbe pins the compatibility property the punch
// probe relies on: a peer built before PunchProbe existed sends a Hello without it,
// and the newer side must read that as "no probe" rather than erroring. If this ever
// broke, the two sides would disagree about how many messages the stream carries and
// the exchange would desynchronise instead of degrading.
func TestHelloDecodesPeerWithoutPunchProbe(t *testing.T) {
	t.Parallel()
	// The Hello shape before PunchProbe was added. gob matches fields by name and
	// ignores the Go type's own name, so this encodes exactly what an older peer does.
	type helloWithoutProbe struct {
		SupportedTiers  []Tier
		WireGuardPubKey [32]byte
	}

	var buf bytes.Buffer
	sent := helloWithoutProbe{SupportedTiers: []Tier{TierLibp2p}, WireGuardPubKey: [32]byte{0xAB}}
	if err := gob.NewEncoder(&buf).Encode(sent); err != nil {
		t.Fatalf("encode: %v", err)
	}

	var got Hello
	if err := gob.NewDecoder(&buf).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.PunchProbe {
		t.Error("PunchProbe = true for a peer that never sent the field, want false")
	}
	if !reflect.DeepEqual(got.SupportedTiers, sent.SupportedTiers) || got.WireGuardPubKey != sent.WireGuardPubKey {
		t.Fatalf("decoded %+v, want the sent fields %+v", got, sent)
	}
}

func TestPunchInfoGobRoundTrip(t *testing.T) {
	t.Parallel()
	want := PunchInfo{
		ICEUfrag:            "ufrag",
		ICEPwd:              "password",
		ICECandidates:       []string{"candidate:1 1 udp ...", "candidate:2 1 udp ..."},
		QUICCertFingerprint: []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(want); err != nil {
		t.Fatalf("encode: %v", err)
	}
	var got PunchInfo
	if err := gob.NewDecoder(&buf).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip mismatch: got %+v, want %+v", got, want)
	}
}

// TestNegotiateExchange drives a full duplex exchange between two independent
// sides, matching how the production callers (host stream handler / client dial)
// invoke Negotiate concurrently against each other.
func TestNegotiateExchange(t *testing.T) {
	t.Parallel()
	hostConn, clientConn := connPair(t)

	clientHello := Hello{SupportedTiers: []Tier{TierQUIC, TierLibp2p}, WireGuardPubKey: [32]byte{0xAA}}
	hostHello := Hello{SupportedTiers: []Tier{TierWireGuard, TierQUIC, TierLibp2p}, WireGuardPubKey: [32]byte{0xBB}}

	type outcome struct {
		tier Tier
		peer Hello
		err  error
	}
	clientOut := make(chan outcome, 1)
	hostOut := make(chan outcome, 1)

	go func() {
		tier, peer, err := NewExchange(clientConn).Negotiate(context.Background(), clientHello)
		clientOut <- outcome{tier, peer, err}
	}()
	go func() {
		tier, peer, err := NewExchange(hostConn).Negotiate(context.Background(), hostHello)
		hostOut <- outcome{tier, peer, err}
	}()

	client := <-clientOut
	host := <-hostOut

	if client.err != nil {
		t.Fatalf("client Negotiate: %v", client.err)
	}
	if host.err != nil {
		t.Fatalf("host Negotiate: %v", host.err)
	}
	// Both sides must independently resolve the same tier: the highest shared, QUIC.
	if client.tier != TierQUIC || host.tier != TierQUIC {
		t.Fatalf("resolved tiers = client %q / host %q, want quic on both", client.tier, host.tier)
	}
	if !reflect.DeepEqual(client.peer, hostHello) {
		t.Errorf("client saw peer hello %+v, want %+v", client.peer, hostHello)
	}
	if !reflect.DeepEqual(host.peer, clientHello) {
		t.Errorf("host saw peer hello %+v, want %+v", host.peer, clientHello)
	}
}

// TestExchangeBothPhases runs Hello and then PunchInfo over a single Exchange, which
// is how the real two-phase handshake uses one stream. It is the regression test for
// sharing one encoder/decoder pair: with a decoder built fresh per phase, the
// bufio.Reader gob wraps around the stream swallows the head of the second message
// and this test hangs or decodes garbage.
func TestExchangeBothPhases(t *testing.T) {
	t.Parallel()
	aConn, bConn := connPair(t)

	aHello := Hello{SupportedTiers: []Tier{TierWireGuard, TierLibp2p}, WireGuardPubKey: [32]byte{0xAA}}
	bHello := Hello{SupportedTiers: []Tier{TierWireGuard, TierQUIC, TierLibp2p}, WireGuardPubKey: [32]byte{0xBB}}
	aInfo := PunchInfo{ICEUfrag: "aaaa", ICEPwd: "apwd", ICECandidates: []string{"a-cand"}}
	bInfo := PunchInfo{ICEUfrag: "bbbb", ICEPwd: "bpwd", ICECandidates: []string{"b-cand"}, QUICCertFingerprint: []byte{0x01, 0x02}}

	type outcome struct {
		tier      Tier
		peerHello Hello
		peerInfo  PunchInfo
		err       error
	}
	// run drives both phases on one side, over one Exchange.
	run := func(conn net.Conn, hello Hello, info PunchInfo) <-chan outcome {
		out := make(chan outcome, 1)
		go func() {
			x := NewExchange(conn)
			tier, peerHello, err := x.Negotiate(context.Background(), hello)
			if err != nil {
				out <- outcome{err: err}
				return
			}
			peerInfo, err := x.ExchangePunchInfo(context.Background(), info)
			out <- outcome{tier: tier, peerHello: peerHello, peerInfo: peerInfo, err: err}
		}()
		return out
	}

	// Start both sides before awaiting either: each phase only completes once its
	// counterpart has sent too.
	aOut := run(aConn, aHello, aInfo)
	bOut := run(bConn, bHello, bInfo)
	a := <-aOut
	b := <-bOut

	if a.err != nil || b.err != nil {
		t.Fatalf("exchange errors: a=%v b=%v", a.err, b.err)
	}
	// Both sides resolve the same tier independently: the highest shared, WireGuard.
	if a.tier != TierWireGuard || b.tier != TierWireGuard {
		t.Fatalf("resolved tiers = a %q / b %q, want wireguard on both", a.tier, b.tier)
	}
	if !reflect.DeepEqual(a.peerHello, bHello) {
		t.Errorf("a saw peer hello %+v, want %+v", a.peerHello, bHello)
	}
	if !reflect.DeepEqual(b.peerHello, aHello) {
		t.Errorf("b saw peer hello %+v, want %+v", b.peerHello, aHello)
	}
	if !reflect.DeepEqual(a.peerInfo, bInfo) {
		t.Errorf("a saw peer punch info %+v, want %+v", a.peerInfo, bInfo)
	}
	if !reflect.DeepEqual(b.peerInfo, aInfo) {
		t.Errorf("b saw peer punch info %+v, want %+v", b.peerInfo, aInfo)
	}
}

// TestExchangeContextCancel proves a caller is not stuck when the peer never
// answers: the phase returns the context error rather than blocking on the read.
func TestExchangeContextCancel(t *testing.T) {
	t.Parallel()
	conn, peer := connPair(t)

	// Drain the local Hello so the write completes, then never reply.
	go func() { _, _ = io.Copy(io.Discard, peer) }()

	ctx, cancel := context.WithCancel(context.Background())
	go cancel()

	_, _, err := NewExchange(conn).Negotiate(ctx, Hello{SupportedTiers: []Tier{TierLibp2p}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Negotiate error = %v, want context.Canceled", err)
	}
}
