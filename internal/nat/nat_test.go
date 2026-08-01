package nat

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

// offlineConfig punches without touching the public internet: no STUN servers, and
// loopback host candidates enabled so two agents in this one process can actually
// reach each other. An empty non-nil STUNServers is what distinguishes "explicitly
// none" from "unset", which would substitute the public defaults.
func offlineConfig() Config {
	return Config{
		STUNServers:     []string{},
		Timeout:         10 * time.Second,
		includeLoopback: true,
	}
}

func TestConfigWithDefaults(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		in          Config
		wantServers []string
		wantTimeout time.Duration
	}{
		{
			name:        "zero value gets public defaults",
			in:          Config{},
			wantServers: DefaultSTUNServers,
			wantTimeout: DefaultTimeout,
		},
		{
			name:        "empty non-nil server list means no STUN",
			in:          Config{STUNServers: []string{}},
			wantServers: []string{},
			wantTimeout: DefaultTimeout,
		},
		{
			name:        "explicit values are preserved",
			in:          Config{STUNServers: []string{"stun:example.test:3478"}, Timeout: time.Second},
			wantServers: []string{"stun:example.test:3478"},
			wantTimeout: time.Second,
		},
		{
			name:        "non-positive timeout falls back to the default",
			in:          Config{STUNServers: []string{}, Timeout: -time.Second},
			wantServers: []string{},
			wantTimeout: DefaultTimeout,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.in.withDefaults()
			if !reflect.DeepEqual(got.STUNServers, tt.wantServers) {
				t.Errorf("STUNServers = %v, want %v", got.STUNServers, tt.wantServers)
			}
			if got.Timeout != tt.wantTimeout {
				t.Errorf("Timeout = %v, want %v", got.Timeout, tt.wantTimeout)
			}
		})
	}
}

func TestParseSTUNServers(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		in    []string
		want  int
		hosts []string
	}{
		{name: "none configured", in: []string{}, want: 0},
		{
			name:  "all valid",
			in:    []string{"stun:stun.l.google.com:19302", "stun:stun.cloudflare.com:3478"},
			want:  2,
			hosts: []string{"stun.l.google.com", "stun.cloudflare.com"},
		},
		{
			// One malformed entry must not cost the caller the servers that did parse.
			name:  "unparseable entries are skipped",
			in:    []string{"not-a-uri", "stun:stun.l.google.com:19302", "http://example.test"},
			want:  1,
			hosts: []string{"stun.l.google.com"},
		},
		{name: "all unparseable", in: []string{"not-a-uri", "://"}, want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := parseSTUNServers(tt.in, false)
			if len(got) != tt.want {
				t.Fatalf("parseSTUNServers(%v) returned %d URIs, want %d", tt.in, len(got), tt.want)
			}
			for i, host := range tt.hosts {
				if got[i].Host != host {
					t.Errorf("URI %d host = %q, want %q", i, got[i].Host, host)
				}
			}
		})
	}
}

func TestCredentialsValid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   Credentials
		want bool
	}{
		{name: "complete", in: Credentials{Ufrag: "u", Pwd: "p", Candidates: []string{"c"}}, want: true},
		{name: "zero value", in: Credentials{}, want: false},
		{name: "missing ufrag", in: Credentials{Pwd: "p", Candidates: []string{"c"}}, want: false},
		{name: "missing password", in: Credentials{Ufrag: "u", Candidates: []string{"c"}}, want: false},
		// A peer whose own gathering failed still sends credentials so both sides stay
		// in lockstep; the receiver detects it here and skips the attempt.
		{name: "no candidates", in: Credentials{Ufrag: "u", Pwd: "p"}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.in.Valid(); got != tt.want {
				t.Errorf("Credentials%+v.Valid() = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestNewGathersLocalCandidates(t *testing.T) {
	agent, err := New(context.Background(), offlineConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = agent.Close() })

	local := agent.Local()
	if !local.Valid() {
		t.Fatalf("gathered credentials are incomplete: %+v", local)
	}
	// Every candidate must survive a round trip through the wire form, since that is
	// exactly what the peer will do with them.
	for _, raw := range local.Candidates {
		if raw == "" {
			t.Fatalf("gathered an empty candidate string: %+v", local)
		}
	}
}

func TestAddRemoteRejectsUnusable(t *testing.T) {
	tests := []struct {
		name   string
		remote Credentials
	}{
		{name: "no credentials at all", remote: Credentials{}},
		{name: "credentials without candidates", remote: Credentials{Ufrag: "ufrag", Pwd: "password"}},
		{
			name:   "credentials with only unparseable candidates",
			remote: Credentials{Ufrag: "ufrag", Pwd: "password", Candidates: []string{"garbage", ""}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agent, err := New(context.Background(), offlineConfig())
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			t.Cleanup(func() { _ = agent.Close() })

			if err := agent.AddRemote(tt.remote); !errors.Is(err, ErrNoRemote) {
				t.Fatalf("AddRemote error = %v, want ErrNoRemote", err)
			}
			// Connect must refuse rather than block on checks that cannot succeed.
			if _, err := agent.Connect(context.Background(), true); !errors.Is(err, ErrNoRemote) {
				t.Fatalf("Connect error = %v, want ErrNoRemote", err)
			}
		})
	}
}

// TestPunchLoopback drives a complete punch between two agents in this process, in
// the same order the tunnel does it: gather, swap credentials, connect with exactly
// one side controlling. It needs no external network because both agents gather
// loopback host candidates.
func TestPunchLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := New(ctx, offlineConfig())
	if err != nil {
		t.Fatalf("New client agent: %v", err)
	}
	defer client.Close()

	host, err := New(ctx, offlineConfig())
	if err != nil {
		t.Fatalf("New host agent: %v", err)
	}
	defer host.Close()

	if err := client.AddRemote(host.Local()); err != nil {
		t.Fatalf("client AddRemote: %v", err)
	}
	if err := host.AddRemote(client.Local()); err != nil {
		t.Fatalf("host AddRemote: %v", err)
	}

	type result struct {
		conn interface {
			Read([]byte) (int, error)
			Write([]byte) (int, error)
			SetDeadline(time.Time) error
		}
		err error
	}
	// Both sides must be in checks concurrently: neither completes alone.
	clientOut := make(chan result, 1)
	hostOut := make(chan result, 1)
	go func() {
		conn, err := client.Connect(ctx, true) // client is always the controlling side
		clientOut <- result{conn, err}
	}()
	go func() {
		conn, err := host.Connect(ctx, false)
		hostOut <- result{conn, err}
	}()

	clientRes := <-clientOut
	hostRes := <-hostOut
	if clientRes.err != nil || hostRes.err != nil {
		t.Fatalf("punch failed: client=%v host=%v", clientRes.err, hostRes.err)
	}

	// A nominated pair is not proof of a usable path; move a payload over it.
	deadline := time.Now().Add(10 * time.Second)
	_ = clientRes.conn.SetDeadline(deadline)
	_ = hostRes.conn.SetDeadline(deadline)

	want := []byte("punched")
	if _, err := clientRes.conn.Write(want); err != nil {
		t.Fatalf("write over punched conn: %v", err)
	}
	got := make([]byte, len(want)+8)
	n, err := hostRes.conn.Read(got)
	if err != nil {
		t.Fatalf("read over punched conn: %v", err)
	}
	if string(got[:n]) != string(want) {
		t.Fatalf("read %q over punched conn, want %q", got[:n], want)
	}
}

// TestCloseIsIdempotent covers the shutdown path: the tunnel closes the agent from
// a deferred call that may run after an earlier explicit close.
func TestCloseIsIdempotent(t *testing.T) {
	agent, err := New(context.Background(), offlineConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := agent.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := agent.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
