package transport

import "testing"

func TestParseNetwork(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		value   string
		want    Network
		wantErr bool
	}{
		{name: "tcp", value: "tcp", want: NetworkTCP},
		{name: "udp", value: "udp", want: NetworkUDP},
		// Rejected rather than folded: the value is passed straight to net.Dial and
		// travels in the token, so accepting a spelling this package would then have
		// to normalise everywhere is worse than refusing it once.
		{name: "wrong case", value: "TCP", wantErr: true},
		{name: "empty", value: "", wantErr: true},
		{name: "padded", value: " tcp", wantErr: true},
		// A real net.Dial network, but not one this tunnel forwards.
		{name: "unsupported network", value: "unix", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParseNetwork(tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseNetwork(%q) = %q, want an error", tt.value, got)
				}
				if got != "" {
					t.Errorf("ParseNetwork(%q) = %q alongside an error, want the zero value", tt.value, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseNetwork(%q): %v", tt.value, err)
			}
			if got != tt.want {
				t.Errorf("ParseNetwork(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

// TestNetworkDatagram pins the one bit every data-plane tier reads off the network.
// Both sides derive it from the same token field, so a tier picking its
// message-oriented sub-mode cannot disagree with the peer about which it is running.
func TestNetworkDatagram(t *testing.T) {
	t.Parallel()

	if NetworkUDP.Datagram() != true {
		t.Error("NetworkUDP.Datagram() = false, want true")
	}
	if NetworkTCP.Datagram() != false {
		t.Error("NetworkTCP.Datagram() = true, want false")
	}
	// The zero value is not a network at all; it must not read as the datagram one,
	// which would silently select a tier's UDP sub-mode for an unset field.
	if (Network("")).Datagram() != false {
		t.Error("the zero Network reports as a datagram network")
	}
}
