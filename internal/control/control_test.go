package control

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/libp2p/go-libp2p/core/test"
)

func TestOutputMarshalOmitsEmptyFields(t *testing.T) {
	t.Parallel()

	// A TOKEN event carries only its action and token; every other field, including
	// the new Tier, must be omitted.
	data, err := json.Marshal(Output{Action: TOKEN, Token: "abc"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(data)
	if want := `{"action":"TOKEN","token":"abc"}`; got != want {
		t.Fatalf("marshal = %s, want %s", got, want)
	}
	if strings.Contains(got, "tier") {
		t.Errorf("empty Tier should be omitted, got %s", got)
	}
}

func TestOutputTierRoundTrip(t *testing.T) {
	t.Parallel()

	id := test.RandPeerIDFatal(t)
	out := Output{
		Action:    CONNECTED,
		SessionId: id,
		Addr:      "/ip4/127.0.0.1/tcp/1234",
		Port:      5555,
		Tier:      "libp2p",
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(out); err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !strings.Contains(buf.String(), `"tier":"libp2p"`) {
		t.Fatalf("expected tier field in output, got %s", buf.String())
	}

	var got Output
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Tier != "libp2p" {
		t.Errorf("Tier = %q, want libp2p", got.Tier)
	}
	if got.SessionId != id {
		t.Errorf("SessionId = %s, want %s", got.SessionId, id)
	}
	if got.Port != 5555 {
		t.Errorf("Port = %d, want 5555", got.Port)
	}
}
