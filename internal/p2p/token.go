package p2p

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"fmt"

	"github.com/libp2p/go-libp2p/core/peer"
)

// Token carries everything a client needs to locate and dial a host: the host's
// peer ID, the network type of the forwarded service, and the host's static
// WireGuard (X25519) public key used by the WireGuard tunnel tier. gob encodes
// fields by name, so a token produced before WireGuardPubKey existed decodes with an
// all-zero key rather than failing.
type Token struct {
	Network         string
	ID              peer.ID
	WireGuardPubKey [32]byte
}

// Encode serialises the token into a base64 string suitable for sharing with
// clients out of band.
func (t Token) Encode() (string, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(t); err != nil {
		return "", fmt.Errorf("encode token: %w", err)
	}

	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// DecodeToken parses a base64 token previously produced by Token.Encode.
func DecodeToken(encoded string) (Token, error) {
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
