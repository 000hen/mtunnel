package p2p

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"testing"

	"mtunnel-libp2p/internal/transport"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/test"
)

// legacyToken is the token exactly as the original build declares it: no Version
// field, and Network as a plain string. Encoding one produces the bytes that build
// produces, which is the only way to test against it without keeping a copy of the
// binary - and the direction that matters most, since an operator holding an old
// token is the case the version exists to diagnose.
type legacyToken struct {
	Network         string
	ID              peer.ID
	WireGuardPubKey [32]byte
}

// futureToken is a token from a build newer than this one. Token.Encode always
// stamps TokenVersionCurrent, so a shadow struct is the only way to write any other
// version - which is the same reason the legacy shape needs one.
type futureToken struct {
	Version         TokenVersion
	Network         transport.Network
	ID              peer.ID
	WireGuardPubKey [32]byte
}

// encodeShadow serialises one of the shadow shapes the way Token.Encode would, so
// what is under test is the decoder's judgement rather than a second encoding.
func encodeShadow(t *testing.T, v any) string {
	t.Helper()

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(v); err != nil {
		t.Fatalf("encode shadow token: %v", err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func randPeerID(t *testing.T) peer.ID {
	t.Helper()

	id, err := test.RandPeerID()
	if err != nil {
		t.Fatalf("RandPeerID: %v", err)
	}
	return id
}

func TestTokenRoundTrip(t *testing.T) {
	t.Parallel()

	id := randPeerID(t)

	var wgKey [32]byte
	for i := range wgKey {
		wgKey[i] = byte(i)
	}

	tests := []struct {
		name  string
		token Token
	}{
		{
			name:  "tcp with wireguard key",
			token: Token{Network: transport.NetworkTCP, ID: id, WireGuardPubKey: wgKey},
		},
		{
			name:  "udp with zero key",
			token: Token{Network: transport.NetworkUDP, ID: id},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			encoded, err := tt.token.Encode()
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			got, err := DecodeToken(encoded)
			if err != nil {
				t.Fatalf("DecodeToken: %v", err)
			}
			if got.Version != TokenVersionCurrent {
				t.Errorf("Version = %d, want %d", got.Version, TokenVersionCurrent)
			}
			if got.Network != tt.token.Network {
				t.Errorf("Network = %q, want %q", got.Network, tt.token.Network)
			}
			if got.ID != tt.token.ID {
				t.Errorf("ID = %s, want %s", got.ID, tt.token.ID)
			}
			if got.WireGuardPubKey != tt.token.WireGuardPubKey {
				t.Errorf("WireGuardPubKey = %x, want %x", got.WireGuardPubKey, tt.token.WireGuardPubKey)
			}
		})
	}
}

// TestEncodeStampsCurrentVersion pins the reason Encode takes a value receiver and
// overwrites the field: the emitted version is a property of the build, not of what
// each call site remembered to set, and a caller cannot pin an old one by accident.
func TestEncodeStampsCurrentVersion(t *testing.T) {
	t.Parallel()

	token := Token{Version: 99, Network: transport.NetworkTCP, ID: randPeerID(t)}
	encoded, err := token.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := decodeToken(encoded)
	if err != nil {
		t.Fatalf("decodeToken: %v", err)
	}
	if got.Version != TokenVersionCurrent {
		t.Errorf("encoded version = %d, want %d", got.Version, TokenVersionCurrent)
	}
	if token.Version != 99 {
		t.Errorf("Encode mutated the caller's token: Version = %d, want 99", token.Version)
	}
}

// TestDecodeTokenRejectsLegacyToken is the whole point of the version field. An
// unversioned token decodes cleanly - gob simply has nothing to put in the field -
// so nothing about the bytes says it is unusable. Only the version check does, and
// it has to happen here rather than several round trips later at a protocol nothing
// is listening on.
func TestDecodeTokenRejectsLegacyToken(t *testing.T) {
	t.Parallel()

	id := randPeerID(t)
	encoded := encodeShadow(t, legacyToken{Network: "tcp", ID: id})

	// The encoding half still succeeds, and reports the legacy version rather than
	// an error: "unversioned" is a value, and the judgement is separate.
	decoded, err := decodeToken(encoded)
	if err != nil {
		t.Fatalf("decodeToken: %v", err)
	}
	if decoded.Version != TokenVersionLegacy {
		t.Errorf("Version = %d, want %d", decoded.Version, TokenVersionLegacy)
	}
	// Network survives the string -> transport.Network change, because gob matches
	// on the underlying kind. This is what makes adding the version field the only
	// incompatibility between the two generations.
	if decoded.Network != transport.NetworkTCP {
		t.Errorf("Network = %q, want %q", decoded.Network, transport.NetworkTCP)
	}
	if decoded.ID != id {
		t.Errorf("ID = %s, want %s", decoded.ID, id)
	}

	if _, err := DecodeToken(encoded); !errors.Is(err, ErrTokenVersionUnsupported) {
		t.Fatalf("DecodeToken error = %v, want it to wrap ErrTokenVersionUnsupported", err)
	}
}

// TestDecodeTokenRejectsFutureVersion covers the other side of the same check: a
// token this build can read the bytes of but cannot act on.
func TestDecodeTokenRejectsFutureVersion(t *testing.T) {
	t.Parallel()

	encoded := encodeShadow(t, futureToken{
		Version: TokenVersionCurrent + 1,
		Network: transport.NetworkTCP,
		ID:      randPeerID(t),
	})

	if _, err := DecodeToken(encoded); !errors.Is(err, ErrTokenVersionUnsupported) {
		t.Fatalf("DecodeToken error = %v, want it to wrap ErrTokenVersionUnsupported", err)
	}
}

// TestLegacyBuildCanReadCurrentToken checks the compatibility claim in the other
// direction, which nothing else exercises: the original build decodes a token from
// this one into a struct with no Version field, drops the field it does not know,
// and reads the rest exactly as it always did. It then fails at the protocol, which
// is the intended failure - but not at the token, which would be the confusing one.
func TestLegacyBuildCanReadCurrentToken(t *testing.T) {
	t.Parallel()

	id := randPeerID(t)
	encoded, err := Token{Network: transport.NetworkUDP, ID: id}.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	var got legacyToken
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&got); err != nil {
		t.Fatalf("original build could not decode this token: %v", err)
	}
	if got.Network != "udp" {
		t.Errorf("Network = %q, want %q", got.Network, "udp")
	}
	if got.ID != id {
		t.Errorf("ID = %s, want %s", got.ID, id)
	}
}

// TestDecodeTokenRejectsUnreadableInput keeps the two failure modes distinct: a
// token that is not a token at all must not be reported as a version problem, or
// the operator is told to upgrade something over a typo.
func TestDecodeTokenRejectsUnreadableInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		encoded string
	}{
		{name: "not base64", encoded: "!!!not base64!!!"},
		{name: "not gob", encoded: base64.StdEncoding.EncodeToString([]byte("hello"))},
		{name: "empty", encoded: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := DecodeToken(tt.encoded)
			if err == nil {
				t.Fatal("DecodeToken succeeded, want an error")
			}
			if errors.Is(err, ErrTokenVersionUnsupported) {
				t.Errorf("error = %v, want an encoding failure rather than a version one", err)
			}
		})
	}
}
