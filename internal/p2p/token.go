package p2p

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"

	"mtunnel-libp2p/internal/transport"

	"github.com/libp2p/go-libp2p/core/peer"
)

// TokenVersion is the generation of the connection token's encoding. It exists so
// that a client handed a token from a build it cannot talk to says so, instead of
// discovering the peer and then failing on a protocol nothing is listening for.
//
// It is a separate axis from ProtocolGeneration: this is how the token is
// written, that is how the streams are spoken. ProtocolsFor maps one to the other.
type TokenVersion uint16

const (
	// TokenVersionLegacy is what a token from before versioning decodes to. gob
	// omits zero values and ignores fields the receiver does not know, so an
	// original token simply arrives with no version at all - which is exactly the
	// signal, and why zero is reserved rather than used.
	TokenVersionLegacy TokenVersion = 0

	// TokenVersionCurrent is the version this build writes and the highest it can
	// read. It is 1 because this is the first token generation to carry a version
	// at all; the unversioned original is 0.
	TokenVersionCurrent TokenVersion = 1
)

// ErrTokenVersionUnsupported reports a token this build cannot act on: either an
// unversioned token from the original binary, or one from a build newer than this
// one. Callers match on it to distinguish "the token is unreadable" from "the
// token is readable and names a peer this build cannot reach".
var ErrTokenVersionUnsupported = errors.New("unsupported token version")

// Token carries everything a client needs to locate and dial a host: the encoding
// version, the host's peer ID, the network type of the forwarded service, and the
// host's static WireGuard (X25519) public key used by the WireGuard tunnel tier.
//
// # Compatibility
//
// gob encodes fields by name, omits zero values, and ignores fields the receiving
// struct does not declare. That makes the version field compatible in both
// directions without any framing of our own:
//
//   - This build reading an original token: Version was never written, so it
//     decodes as TokenVersionLegacy - which is the detection, not a failure.
//   - The original build reading this token: Version is a field it does not know,
//     so gob drops it and the rest decodes exactly as it always did.
//
// Network moving from string to transport.Network is safe for the same reason:
// gob matches on the underlying kind, not the declared Go type, so the bytes are
// unchanged. Adding a field is compatible; changing a field's *kind* or reusing a
// name for a different meaning is not - do that with a new TokenVersion instead.
type Token struct {
	// Version is stamped by Encode and must not be set by callers; see Encode.
	Version         TokenVersion
	Network         transport.Network
	ID              peer.ID
	WireGuardPubKey [32]byte
}

// Encode serialises the token into a base64 string suitable for sharing with
// clients out of band.
//
// It always stamps TokenVersionCurrent, whatever the caller left in the field, so
// that "this build emits this version" is a property of the code rather than of
// what each call site remembered to set. The receiver is a value, so the caller's
// token is untouched.
func (t Token) Encode() (string, error) {
	t.Version = TokenVersionCurrent

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(t); err != nil {
		return "", fmt.Errorf("encode token: %w", err)
	}

	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// DecodeToken parses a base64 token previously produced by Token.Encode and
// checks that this build can act on its version.
//
// Version checking belongs here rather than at the first use of the token: every
// caller wants the same answer, and the point of the version is to fail at the
// moment the token is read rather than several network round trips later. The
// error wraps ErrTokenVersionUnsupported and names both versions, so the operator
// is told which side to upgrade.
func DecodeToken(encoded string) (Token, error) {
	token, err := decodeToken(encoded)
	if err != nil {
		return Token{}, err
	}
	if _, err := ProtocolsFor(token.Version); err != nil {
		return Token{}, err
	}
	return token, nil
}

// decodeToken performs the encoding half only, with no version judgement. It is
// separate so the version rules can be tested against tokens this build would
// refuse - including synthesised originals - without a second encoder.
func decodeToken(encoded string) (Token, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return Token{}, fmt.Errorf("decode token base64: %w", err)
	}

	var token Token
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&token); err != nil {
		return Token{}, fmt.Errorf("decode token data: %w", err)
	}

	return token, nil
}
