package tier

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"testing"

	"mtunnel-libp2p/internal/negotiate"
	"mtunnel-libp2p/internal/quictun"
	"mtunnel-libp2p/internal/wireguard"
)

func testSet(t *testing.T) *Set {
	t.Helper()

	ids, err := NewIdentities()
	if err != nil {
		t.Fatalf("NewIdentities: %v", err)
	}
	return NewSet(ids, Params{})
}

// TestSetOrderFollowsCascade is the invariant that lets tier selection cost no extra
// round trip: both sides walk the ladder independently and must reach the same
// answer, so the order comes from the negotiate wire contract rather than from the
// order implementations happens to be written in. Reordering that table must not
// change what a session negotiates.
func TestSetOrderFollowsCascade(t *testing.T) {
	t.Parallel()

	var want []negotiate.Tier
	for _, id := range negotiate.Cascade() {
		if id != negotiate.TierLibp2p {
			want = append(want, id)
		}
	}

	got := testSet(t).IDs()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("IDs() = %v, want %v", got, want)
	}
	// The floor is not a tier in this sense - there is no substrate to stand up -
	// so callers append it themselves and the registry must not supply it.
	for _, id := range got {
		if id == negotiate.TierLibp2p {
			t.Error("IDs() includes the libp2p floor")
		}
	}
}

// TestSetIDsIsACopy guards the accessor: a caller narrowing the list for a forced
// tunnel mode appends to what it gets back, and must not be editing the registry.
func TestSetIDsIsACopy(t *testing.T) {
	t.Parallel()

	set := testSet(t)
	ids := set.IDs()
	if len(ids) == 0 {
		t.Fatal("no tiers registered")
	}
	ids[0] = "clobbered"

	if again := set.IDs(); again[0] == "clobbered" {
		t.Error("IDs() handed out the registry's own slice")
	}
}

func TestSetLookup(t *testing.T) {
	t.Parallel()

	set := testSet(t)
	for _, id := range set.IDs() {
		impl, ok := set.Lookup(id)
		if !ok {
			t.Fatalf("Lookup(%q) reported no implementation for a registered tier", id)
		}
		// The registry is keyed by what the implementation calls itself, so a tier
		// filed under someone else's ID would be dialled for the wrong rung.
		if impl.ID() != id {
			t.Errorf("tier registered as %q reports ID %q", id, impl.ID())
		}
	}

	if _, ok := set.Lookup(negotiate.TierLibp2p); ok {
		t.Error("Lookup(libp2p) found an implementation; the floor is not a rung")
	}
	if _, ok := set.Lookup("nonesuch"); ok {
		t.Error("Lookup found an implementation for an unknown tier")
	}
}

// TestSetRejectsUnimplementedTier covers the peer-is-newer case. The peer names the
// rungs, so a tier this build has never heard of has to be an ordinary failed
// attempt - the cascade moves to the next rung - rather than a panic.
func TestSetRejectsUnimplementedTier(t *testing.T) {
	t.Parallel()

	set := testSet(t)
	ctx := context.Background()

	// A substrate that would fail loudly if either call actually reached a tier.
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })

	tests := []struct {
		name string
		call func() (Rung, Outcome, error)
	}{
		{name: "dial", call: func() (Rung, Outcome, error) {
			return set.Dial(ctx, "from-the-future", client, Session{})
		}},
		{name: "serve", call: func() (Rung, Outcome, error) {
			return set.Serve(ctx, "from-the-future", server, Session{})
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rung, outcome, err := tt.call()
			if err == nil {
				t.Fatal("succeeded on a tier this build does not implement")
			}
			if outcome != OutcomeUnsupported {
				t.Errorf("outcome = %q, want %q", outcome, OutcomeUnsupported)
			}
			if rung.Opener != nil || rung.Acceptor != nil || rung.Close != nil {
				t.Errorf("rung = %+v, want the zero value alongside an error", rung)
			}
		})
	}
}

// TestSetSubstrateAbandoned is what stops the cascade walking onto a closed conn.
// The question is asked of the Set rather than of a tier because by the time it is
// asked the rung has been released and its error composed with unrelated teardown
// failures - which tier produced it is no longer answerable, and no longer the
// point: what matters is whether there is anything left to run the next rung on.
func TestSetSubstrateAbandoned(t *testing.T) {
	t.Parallel()

	set := testSet(t)

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "unrelated", err: errors.New("handshake timed out"), want: false},
		{name: "wireguard sentinel", err: wireguard.ErrSubstrateAbandoned, want: true},
		{name: "quic sentinel", err: quictun.ErrSubstrateAbandoned, want: true},
		{
			// The shape the cascade actually sees: the sentinel wrapped by the rung's
			// own teardown and then again by the caller.
			name: "wrapped twice",
			err:  fmt.Errorf("close rung: %w", fmt.Errorf("release device: %w", wireguard.ErrSubstrateAbandoned)),
			want: true,
		},
		{
			name: "joined with an unrelated failure",
			err:  errors.Join(errors.New("listener close failed"), quictun.ErrSubstrateAbandoned),
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := set.SubstrateAbandoned(tt.err); got != tt.want {
				t.Errorf("SubstrateAbandoned(%v) = %t, want %t", tt.err, got, tt.want)
			}
		})
	}
}

// TestNewSetPanicsWithoutIdentity pins the wiring check. A tier built over a missing
// credential does not fail here - it fails as a handshake that never completes, on a
// live tunnel, which is the wrong place to find out.
func TestNewSetPanicsWithoutIdentity(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Error("NewSet accepted identities missing a registered tier's credential")
		}
	}()
	NewSet(Identities{byKind: map[negotiate.Tier]Identity{}}, Params{})
}
