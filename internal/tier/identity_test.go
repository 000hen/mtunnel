package tier

import (
	"testing"

	"mtunnel-libp2p/internal/negotiate"
)

func testIdentities(t *testing.T) Identities {
	t.Helper()

	ids, err := NewIdentities()
	if err != nil {
		t.Fatalf("NewIdentities: %v", err)
	}
	return ids
}

// TestIdentitiesCoverEveryImplementation is the check that the two halves of a
// registration stay married: every tier this build implements has a credential, and
// the credential agrees about which tier it belongs to. Getting this wrong once
// meant a tier built over a zero key, which presents as a handshake that never
// completes rather than as anything pointing at the wiring.
func TestIdentitiesCoverEveryImplementation(t *testing.T) {
	t.Parallel()

	ids := testIdentities(t)
	for _, impl := range implementations {
		id, ok := ids.Lookup(impl.kind)
		if !ok {
			t.Errorf("no identity for registered tier %q", impl.kind)
			continue
		}
		if id.Kind() != impl.kind {
			t.Errorf("tier %q holds an identity of kind %q", impl.kind, id.Kind())
		}
		// Kind is what pairs an identity with a tier, so it has to be the same value
		// the tier answers with - see Identity.Kind.
		if built := impl.build(id, Params{}); built.ID() != id.Kind() {
			t.Errorf("tier %q built from a %q identity reports ID %q", impl.kind, id.Kind(), built.ID())
		}
	}

	if _, ok := ids.Lookup(negotiate.TierLibp2p); ok {
		t.Error("the libp2p floor has an identity; it has no substrate of its own to authenticate")
	}
}

// TestIdentitiesAreFreshPerCall pins the "nothing is persisted between runs"
// property for the tier credentials specifically: a restart is a new identity on
// every axis, exactly like the libp2p peer ID.
func TestIdentitiesAreFreshPerCall(t *testing.T) {
	t.Parallel()

	first, second := testIdentities(t), testIdentities(t)

	if first.WireGuardPublicKey() == second.WireGuardPublicKey() {
		t.Error("two NewIdentities calls produced the same WireGuard key")
	}
	if first.QUICFingerprint() == second.QUICFingerprint() {
		t.Error("two NewIdentities calls produced the same QUIC certificate")
	}
}

// TestIdentityFor covers the generic accessor's three answers, since the difference
// between them is what keeps a missing tier from becoming a panic.
func TestIdentityFor(t *testing.T) {
	t.Parallel()

	ids := testIdentities(t)

	wg, ok := IdentityFor[WireGuardIdentity](ids, negotiate.TierWireGuard)
	if !ok {
		t.Fatal("no WireGuard identity")
	}
	if wg.Private == ([32]byte{}) || wg.Public == ([32]byte{}) {
		t.Error("WireGuard identity has a zero half")
	}

	quic, ok := IdentityFor[QUICIdentity](ids, negotiate.TierQUIC)
	if !ok {
		t.Fatal("no QUIC identity")
	}
	if quic.Identity == nil {
		t.Fatal("QUIC identity holds no certificate")
	}

	// A kind this build has no tier for: the zero value and false, not a panic.
	if _, ok := IdentityFor[WireGuardIdentity](ids, "nonesuch"); ok {
		t.Error("IdentityFor found a credential for an unregistered tier")
	}
	// Registered, but asked for as the wrong concrete type. Also false rather than a
	// panic, because the type assertion is the caller's mistake to be told about.
	if _, ok := IdentityFor[QUICIdentity](ids, negotiate.TierWireGuard); ok {
		t.Error("IdentityFor returned a WireGuard credential as a QUIC one")
	}
}

// TestAdvertisedMaterialMatchesTheIdentities checks that what goes on the wire is
// what the tier will actually authenticate with. The public key travels in the
// token and the fingerprint in the punch exchange, and a mismatch either way is a
// tier that negotiates successfully and then fails to hand shake.
func TestAdvertisedMaterialMatchesTheIdentities(t *testing.T) {
	t.Parallel()

	ids := testIdentities(t)

	wg, _ := IdentityFor[WireGuardIdentity](ids, negotiate.TierWireGuard)
	if got := ids.WireGuardPublicKey(); got != wg.Public {
		t.Errorf("advertised WireGuard key = %x, want %x", got, wg.Public)
	}

	quic, _ := IdentityFor[QUICIdentity](ids, negotiate.TierQUIC)
	if got := ids.QUICFingerprint(); got != quic.Fingerprint {
		t.Errorf("advertised QUIC fingerprint = %x, want %x", got, quic.Fingerprint)
	}
	if ids.QUICFingerprint() == ([32]byte{}) {
		t.Error("advertised QUIC fingerprint is zero, which quictun rejects as missing")
	}
}

// TestAdvertisedMaterialWithoutIdentities covers the documented degradation: a
// build (or a zero value) without a tier advertises the zero credential, which
// makes that tier unusable to the peer rather than half-configured - and must not
// panic on the way, since the public halves are read whether or not the tier is
// offered.
func TestAdvertisedMaterialWithoutIdentities(t *testing.T) {
	t.Parallel()

	var none Identities
	if got := none.WireGuardPublicKey(); got != ([32]byte{}) {
		t.Errorf("WireGuardPublicKey() = %x, want the zero key", got)
	}
	if got := none.QUICFingerprint(); got != ([32]byte{}) {
		t.Errorf("QUICFingerprint() = %x, want the zero fingerprint", got)
	}
	if _, ok := none.Lookup(negotiate.TierWireGuard); ok {
		t.Error("the zero Identities reported a credential")
	}
}
