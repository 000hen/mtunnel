package p2p

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/libp2p/go-libp2p/core/protocol"
)

// Generation 1's protocol IDs, kept here as literals because that is precisely the
// point: they are not constants this build has any other use for, and the test is
// that nothing in it collides with them.
const (
	gen1Data      protocol.ID = "/mtunnel/1.0.0"
	gen1Negotiate protocol.ID = "/mtunnel/negotiate/1.0.0"
)

// TestProtocolsDoNotCollideWithGeneration1 is the regression test for why this
// generation exists at all. The two builds cannot interoperate - the token, the
// negotiate exchange, and the tier cascade have all moved - so they must not meet
// on a shared protocol ID and half-negotiate before failing somewhere that says
// nothing about the cause. A peer finding nothing registered fails immediately,
// which is the diagnosable outcome.
func TestProtocolsDoNotCollideWithGeneration1(t *testing.T) {
	t.Parallel()

	current := CurrentProtocols()
	if current.Data == gen1Data {
		t.Errorf("data protocol %q is generation 1's", current.Data)
	}
	if current.Negotiate == gen1Negotiate {
		t.Errorf("negotiate protocol %q is generation 1's", current.Negotiate)
	}
	if current.Data == current.Negotiate {
		t.Errorf("data and negotiate share the protocol ID %q", current.Data)
	}

	// The IDs and the generation constant are written independently, so the check
	// is that they still agree - a bumped constant with an unbumped ID would put
	// this build back on generation 1's channel.
	version := fmt.Sprintf("/%d.0.0", ProtocolGeneration)
	for _, id := range []protocol.ID{current.Data, current.Negotiate} {
		if !strings.HasSuffix(string(id), version) {
			t.Errorf("protocol %q does not carry generation %d", id, ProtocolGeneration)
		}
	}
}

func TestProtocolsFor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		version TokenVersion
		want    Protocols
		wantErr bool
	}{
		{
			name:    "current",
			version: TokenVersionCurrent,
			want:    CurrentProtocols(),
		},
		{
			// The unversioned original. It is an error rather than a fallback to
			// /mtunnel/1.0.0 because this build cannot speak that generation, only
			// name it.
			name:    "legacy is unsupported",
			version: TokenVersionLegacy,
			wantErr: true,
		},
		{
			name:    "future is unsupported",
			version: TokenVersionCurrent + 1,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ProtocolsFor(tt.version)
			if tt.wantErr {
				if !errors.Is(err, ErrTokenVersionUnsupported) {
					t.Fatalf("error = %v, want it to wrap ErrTokenVersionUnsupported", err)
				}
				if got != (Protocols{}) {
					t.Errorf("protocols = %+v, want the zero value alongside an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ProtocolsFor(%d): %v", tt.version, err)
			}
			if got != tt.want {
				t.Errorf("protocols = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestProtocolsForNamesBothSides checks the errors are actionable rather than
// merely correct: each names which side is behind, since the operator's next move
// differs entirely between the two.
func TestProtocolsForNamesBothSides(t *testing.T) {
	t.Parallel()

	_, err := ProtocolsFor(TokenVersionLegacy)
	if err == nil || !strings.Contains(err.Error(), "upgrade the host") {
		t.Errorf("legacy error = %v, want it to name the host as the side to upgrade", err)
	}

	_, err = ProtocolsFor(TokenVersionCurrent + 1)
	if err == nil || !strings.Contains(err.Error(), "upgrade the client") {
		t.Errorf("future error = %v, want it to name the client as the side to upgrade", err)
	}
}
