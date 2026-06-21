package tunnel

import (
	"log"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

// remoteDisconnectWatcher shuts the client down when its target host goes away
// entirely. It implements network.Notifiee.
type remoteDisconnectWatcher struct {
	target peer.ID
	notify func(string)
}

func newRemoteDisconnectWatcher(target peer.ID, notify func(string)) *remoteDisconnectWatcher {
	return &remoteDisconnectWatcher{target: target, notify: notify}
}

func (w *remoteDisconnectWatcher) Listen(network.Network, ma.Multiaddr)         {}
func (w *remoteDisconnectWatcher) ListenClose(network.Network, ma.Multiaddr)    {}
func (w *remoteDisconnectWatcher) Connected(network.Network, network.Conn)      {}
func (w *remoteDisconnectWatcher) OpenedStream(network.Network, network.Stream) {}
func (w *remoteDisconnectWatcher) ClosedStream(network.Network, network.Stream) {}
func (w *remoteDisconnectWatcher) Disconnected(n network.Network, conn network.Conn) {
	if conn.RemotePeer() != w.target {
		return
	}

	// A single connection closing does not mean the peer is gone. libp2p routinely
	// cycles connections during hole punching: the initial limited relay connection
	// is torn down once a direct connection is established, and a direct connection
	// can later drop back to the relay as a fallback. Either event would otherwise
	// be misread as the remote peer disconnecting.
	//
	// Connectedness reports three live states - Connected (a direct connection),
	// Limited (only a relay/limited connection), and NotConnected. Both Connected
	// and Limited still carry traffic (the client opens streams over limited
	// connections via WithAllowLimitedConn), so the peer is only truly gone when no
	// connection of either kind remains.
	if n.Connectedness(w.target) != network.NotConnected {
		return
	}

	log.Printf("Remote peer %s disconnected", w.target)
	if w.notify != nil {
		w.notify("remote peer disconnected")
	}
}
