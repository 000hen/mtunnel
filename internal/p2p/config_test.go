package p2p

import "testing"

func TestParseConnectionMode(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		value   string
		want    ConnectionMode
		wantErr bool
	}{
		{name: "direct only", value: "direct-only", want: ConnectionDirectOnly},
		{name: "direct first case insensitive", value: "DIRECT-FIRST", want: ConnectionDirectFirst},
		{name: "relay only", value: "relay-only", want: ConnectionRelayOnly},
		{name: "invalid", value: "automatic", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseConnectionMode(tt.value)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseConnectionMode(%q) error = %v, wantErr %v", tt.value, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("ParseConnectionMode(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestParseTransportMode(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"default", "quic", "tcp", "webrtc"} {
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseTransportMode(value); err != nil {
				t.Fatalf("ParseTransportMode(%q): %v", value, err)
			}
		})
	}
	if _, err := ParseTransportMode("webtransport"); err == nil {
		t.Fatal("ParseTransportMode(webtransport) unexpectedly succeeded")
	}
}

func TestParseDHTMode(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"close-after-connect", "no-refresh", "current"} {
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseDHTMode(value); err != nil {
				t.Fatalf("ParseDHTMode(%q): %v", value, err)
			}
		})
	}
}
