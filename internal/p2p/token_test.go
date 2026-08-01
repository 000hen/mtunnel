package p2p

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/test"
)

func TestTokenRoundTrip(t *testing.T) {
	t.Parallel()

	id, err := test.RandPeerID()
	if err != nil {
		t.Fatalf("RandPeerID: %v", err)
	}

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
			token: Token{Network: "tcp", ID: id, WireGuardPubKey: wgKey},
		},
		{
			name:  "udp with zero key",
			token: Token{Network: "udp", ID: id},
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
