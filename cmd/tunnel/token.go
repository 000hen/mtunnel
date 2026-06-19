package main

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"fmt"

	"github.com/libp2p/go-libp2p/core/peer"
)

// ConnToken carries everything a client needs to locate and dial a host: the
// host's peer ID and the network type of the forwarded service.
type ConnToken struct {
	Network string
	ID      peer.ID
}

// Encode serialises the token into a base64 string suitable for sharing with
// clients out of band.
func (t ConnToken) Encode() (string, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(t); err != nil {
		return "", fmt.Errorf("encode token: %w", err)
	}

	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// DecodeToken parses a base64 token previously produced by ConnToken.Encode.
func DecodeToken(encoded string) (ConnToken, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return ConnToken{}, fmt.Errorf("decode token base64: %w", err)
	}

	var token ConnToken
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&token); err != nil {
		return ConnToken{}, fmt.Errorf("decode token data: %w", err)
	}

	return token, nil
}
