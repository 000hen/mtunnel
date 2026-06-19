package main

import (
	"log"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

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

	// A single connection closing does not mean the peer is gone. libp2p
	// routinely tears down the initial (limited) relay connection once a
	// direct connection has been established via hole punching, which would
	// otherwise be misread as the remote peer disconnecting. Only treat the
	// peer as disconnected when no live connection to it remains.
	if n.Connectedness(w.target) == network.Connected {
		return
	}

	log.Printf("Remote peer %s disconnected", w.target)
	if w.notify != nil {
		w.notify("remote peer disconnected")
	}
}
