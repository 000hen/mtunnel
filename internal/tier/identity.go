package tier

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"

	"mtunnel-libp2p/internal/negotiate"
	"mtunnel-libp2p/internal/quictun"
)

// Identity is one tier's ephemeral credential for this process: the WireGuard
// static keypair, the QUIC leaf certificate, whatever a future rung needs.
//
// It is an interface rather than a struct with a field per tier for the same
// reason Tier is one. A struct naming every tier's credential is a second place
// that has to be edited when a rung is added, and the easiest of the two to
// forget - the failure mode being a tier built with a zero credential, which
// surfaces as a handshake that never completes rather than as a missing field.
//
// Every implementation is generated fresh per process and never persisted,
// matching the libp2p peer identity: a restart is a new identity on every axis.
// All of them are generated whatever the tunnel mode, because the mode decides
// which tiers this side *offers*, and a peer that withheld a credential would
// force the libp2p floor on a session that could have used something better.
type Identity interface {
	// Kind names the tier these credentials belong to - the same value as that
	// tier's Tier.ID, which is what lets Set pair the two.
	//
	// Kind rather than ID because an identity's own id would be something else
	// entirely: a key fingerprint, a certificate serial. This says which kind of
	// credential it is, not which credential.
	Kind() negotiate.Tier
}

// WireGuardIdentity is one side's static X25519 identity for the WireGuard tier.
//
// stdlib X25519 keys are byte-compatible with WireGuard's key format: both derive
// the public key with curve25519.X25519(scalar, basepoint), which clamps
// internally, so neither side has to clamp for the other.
type WireGuardIdentity struct {
	Private [32]byte
	Public  [32]byte
}

func (WireGuardIdentity) Kind() negotiate.Tier { return negotiate.TierWireGuard }

// NewWireGuardIdentity generates a fresh WireGuard static keypair.
func NewWireGuardIdentity() (WireGuardIdentity, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return WireGuardIdentity{}, fmt.Errorf("generate WireGuard keypair: %w", err)
	}
	var id WireGuardIdentity
	copy(id.Private[:], key.Bytes())
	copy(id.Public[:], key.PublicKey().Bytes())
	return id, nil
}

// QUICIdentity is this side's self-signed leaf certificate for the QUIC tier.
//
// It wraps quictun's own type rather than restating it: the certificate and its
// fingerprint are quictun's to define, and this adds only the one thing the
// registry needs, which is what tier the credential belongs to.
type QUICIdentity struct {
	*quictun.Identity
}

func (QUICIdentity) Kind() negotiate.Tier { return negotiate.TierQUIC }

// NewQUICIdentity generates a fresh self-signed leaf for this run.
func NewQUICIdentity() (QUICIdentity, error) {
	id, err := quictun.NewIdentity()
	if err != nil {
		return QUICIdentity{}, fmt.Errorf("generate QUIC identity: %w", err)
	}
	return QUICIdentity{Identity: id}, nil
}

// Identities is every credential this process serves with, one per tier this
// build implements, keyed by kind.
//
// It is opaque rather than a plain map so that the only way to populate it is
// NewIdentities, which fills it from the same table Set builds from - the two
// cannot end up describing different sets of tiers.
type Identities struct {
	byKind map[negotiate.Tier]Identity
}

// NewIdentities generates one credential per registered tier.
//
// It panics if an implementation's identity constructor produces a credential of
// a different kind than the entry it was registered under, which is a wiring
// mistake rather than a runtime condition - the effect would be a tier handed
// someone else's credential.
func NewIdentities() (Identities, error) {
	ids := Identities{byKind: make(map[negotiate.Tier]Identity, len(implementations))}
	for _, impl := range implementations {
		id, err := impl.identity()
		if err != nil {
			return Identities{}, err
		}
		if id.Kind() != impl.kind {
			panic(fmt.Sprintf("tier: %q registered an identity of kind %q", impl.kind, id.Kind()))
		}
		ids.byKind[impl.kind] = id
	}
	return ids, nil
}

// Lookup returns the credential registered for kind, if this build has one.
func (i Identities) Lookup(kind negotiate.Tier) (Identity, bool) {
	id, ok := i.byKind[kind]
	return id, ok
}

// IdentityFor returns the credential for kind as its concrete type.
//
// It is a function rather than a method because Go has no generic methods. The
// second return distinguishes "this build has no such tier" from a usable
// credential, so a caller reading public material gets the zero value rather than
// a panic - which matters because the public halves are advertised whether or not
// the tier is offered.
func IdentityFor[I Identity](ids Identities, kind negotiate.Tier) (I, bool) {
	id, ok := ids.byKind[kind]
	if !ok {
		var zero I
		return zero, false
	}
	typed, ok := id.(I)
	return typed, ok
}

// WireGuardPublicKey is the key this side advertises in its token and its Hello.
// A build without the WireGuard tier advertises the zero key, which is what makes
// the tier unusable to the peer rather than half-configured.
func (i Identities) WireGuardPublicKey() [32]byte {
	id, _ := IdentityFor[WireGuardIdentity](i, negotiate.TierWireGuard)
	return id.Public
}

// QUICFingerprint is the certificate hash this side advertises in its PunchInfo,
// for the peer to pin the QUIC tier to. The zero fingerprint is what quictun
// rejects with an error naming the missing value rather than a mismatch.
func (i Identities) QUICFingerprint() [32]byte {
	id, ok := IdentityFor[QUICIdentity](i, negotiate.TierQUIC)
	if !ok || id.Identity == nil {
		return [32]byte{}
	}
	return id.Fingerprint
}
