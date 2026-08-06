package tier

import (
	"context"
	"fmt"
	"net"

	"mtunnel-libp2p/internal/negotiate"
)

// implementation is one tier this build provides: which kind it is, how to
// generate the per-process credential it serves with, and how to build it from
// one.
//
// Pairing the two constructors is the point. Credentials and implementations were
// previously registered in separate lists, which meant adding a rung was two
// edits with nothing connecting them - and the one that is easy to forget is the
// credential, whose absence shows up as a handshake that never completes rather
// than as a compile error.
type implementation struct {
	kind     negotiate.Tier
	identity func() (Identity, error)
	build    func(Identity, Params) Tier
}

// implementations is the single registration point for tiers above the libp2p
// floor. Adding one is a file implementing Tier, an entry here, and a constant in
// negotiate's cascade; nothing in internal/tunnel changes.
//
// The assertion in each build is safe because it reads what the identity on the
// same line produced: the two constructors in an entry are written for each other,
// and NewIdentities checks that the credential's own Kind agrees before it is ever
// stored.
var implementations = []implementation{
	{
		kind:     negotiate.TierWireGuard,
		identity: func() (Identity, error) { id, err := NewWireGuardIdentity(); return id, err },
		build:    func(id Identity, p Params) Tier { return newWireGuard(id.(WireGuardIdentity), p) },
	},
	{
		kind:     negotiate.TierQUIC,
		identity: func() (Identity, error) { id, err := NewQUICIdentity(); return id, err },
		build:    func(id Identity, p Params) Tier { return newQUIC(id.(QUICIdentity), p) },
	},
}

// Set is the registry of tiers this build implements, live and bound to this
// process's credentials: the single source of truth for which rungs exist,
// mirroring what tunnel.transportFor is for forwarded networks.
//
// Registration order is not preference order. The cascade's priority is part of the
// negotiate wire contract, because both sides walk it independently and must reach
// the same answer without another round trip - so a Set orders itself by
// negotiate.Cascade rather than by how implementations happens to list its tiers,
// and the two cannot drift apart.
type Set struct {
	order []negotiate.Tier
	byID  map[negotiate.Tier]Tier
}

// NewSet builds every registered tier over the credentials in ids.
//
// It panics if a registered tier has no credential, if two register the same ID,
// or if one is not named in negotiate.Cascade. All three are wiring mistakes
// rather than runtime conditions - the wrong outcome is a tier that silently never
// runs - and NewSet is called once per process at startup, before anything is
// serving.
func NewSet(ids Identities, params Params) *Set {
	set := &Set{byID: make(map[negotiate.Tier]Tier, len(implementations))}
	for _, impl := range implementations {
		id, ok := ids.Lookup(impl.kind)
		if !ok {
			panic(fmt.Sprintf("tier: no identity for %q", impl.kind))
		}
		t := impl.build(id, params)
		if _, dup := set.byID[t.ID()]; dup {
			panic(fmt.Sprintf("tier: %q registered twice", t.ID()))
		}
		set.byID[t.ID()] = t
	}

	// Ordered by the wire contract, and checked against it: a tier the cascade does
	// not name would never be selected, so it is registered in vain.
	for _, id := range negotiate.Cascade() {
		if _, ok := set.byID[id]; ok {
			set.order = append(set.order, id)
		}
	}
	if len(set.order) != len(set.byID) {
		panic("tier: a registered tier is absent from negotiate.Cascade")
	}
	return set
}

// IDs returns the tiers this build implements, highest priority first.
//
// The libp2p floor is not among them: it is not a tier in this sense - it is the
// libp2p stack both processes are already running, with no substrate of its own to
// stand up - so callers advertising their support append it themselves.
func (s *Set) IDs() []negotiate.Tier {
	return append([]negotiate.Tier(nil), s.order...)
}

// Lookup returns the implementation of id, if this build has one.
func (s *Set) Lookup(id negotiate.Tier) (Tier, bool) {
	t, ok := s.byID[id]
	return t, ok
}

// Dial builds the client half of id on substrate. A tier this build does not
// implement is an ordinary failed attempt rather than a panic: the peer names the
// rungs, and a peer running a newer build can legitimately name one this side has
// never heard of.
func (s *Set) Dial(ctx context.Context, id negotiate.Tier, substrate net.Conn, session Session) (Rung, Outcome, error) {
	t, ok := s.Lookup(id)
	if !ok {
		return Rung{}, OutcomeUnsupported, fmt.Errorf("no client implementation for tier %q", id)
	}
	return t.Dial(ctx, substrate, session)
}

// Serve builds the host half of id on substrate, with the same treatment of an
// unimplemented tier as Dial.
func (s *Set) Serve(ctx context.Context, id negotiate.Tier, substrate net.Conn, session Session) (Rung, Outcome, error) {
	t, ok := s.Lookup(id)
	if !ok {
		return Rung{}, OutcomeUnsupported, fmt.Errorf("no host implementation for tier %q", id)
	}
	return t.Serve(ctx, substrate, session)
}

// SubstrateAbandoned reports whether err means some tier's teardown gave up on
// releasing the shared substrate and closed it.
//
// It asks every registered tier because the error surfaces where the *cascade* has
// to act on it - after a rung has been released, often composed with unrelated
// teardown errors - and by then which tier produced it is no longer the question.
// What matters is only whether there is anything left to run the next rung on.
func (s *Set) SubstrateAbandoned(err error) bool {
	if err == nil {
		return false
	}
	for _, t := range s.byID {
		if t.SubstrateAbandoned(err) {
			return true
		}
	}
	return false
}
