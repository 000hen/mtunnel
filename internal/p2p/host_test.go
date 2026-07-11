package p2p

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

func TestSelectAddresses(t *testing.T) {
	t.Parallel()
	direct := ma.StringCast("/ip4/203.0.113.1/tcp/4001")
	relay := ma.StringCast("/ip4/198.51.100.1/tcp/4001/p2p-circuit")
	info := peer.AddrInfo{ID: "12D3KooWTarget", Addrs: []ma.Multiaddr{direct, relay}}

	t.Run("direct modes preserve all discovered addresses", func(t *testing.T) {
		t.Parallel()
		got, err := selectAddresses(info, ConnectionDirectFirst, TransportDefault)
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Addrs) != 2 {
			t.Fatalf("got %d addresses, want 2", len(got.Addrs))
		}
	})

	t.Run("relay only filters direct addresses", func(t *testing.T) {
		t.Parallel()
		got, err := selectAddresses(info, ConnectionRelayOnly, TransportDefault)
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Addrs) != 1 || !got.Addrs[0].Equal(relay) {
			t.Fatalf("got %v, want only %s", got.Addrs, relay)
		}
	})

	t.Run("relay only fails clearly without relay address", func(t *testing.T) {
		t.Parallel()
		_, err := selectAddresses(peer.AddrInfo{ID: info.ID, Addrs: []ma.Multiaddr{direct}}, ConnectionRelayOnly, TransportDefault)
		if err == nil {
			t.Fatal("selectAddresses unexpectedly succeeded")
		}
	})
}

func TestRelayCandidatesRejectsIncompleteAddress(t *testing.T) {
	t.Parallel()
	if _, err := relayCandidates([]string{"/ip4/198.51.100.1/tcp/4001"}); err == nil {
		t.Fatal("relayCandidates unexpectedly accepted an address without a peer ID")
	}
}
