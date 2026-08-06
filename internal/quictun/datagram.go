package quictun

import (
	"context"
	"log/slog"

	"mtunnel-libp2p/internal/flowmux"
)

// A QUIC connection has exactly one datagram channel, but the tunnel forwards many
// independent flows over it - one per UDP source address on the client. Naming the
// flow in each message is what sorts them back out, and that scheme is shared with
// WireGuard's UDP sub-mode rather than reinvented here: see internal/flowmux for the
// wire format and why an unreliable channel is the right one for forwarded UDP.
//
// All this file does is give the mux a QUIC datagram channel to run on.

// newMux builds the flow multiplexer over this connection's datagram channel.
func (t *Tunnel) newMux(dialing bool) *flowmux.Mux {
	t.datagram = newDatagramCodec(t.conn.SendDatagram, t.recvDatagram)
	return flowmux.New(flowmux.Config{
		Send:    t.datagram.Send,
		Recv:    t.datagram.Recv,
		Dialing: dialing,
		OnDrop:  t.logFlowDrop,
	})
}

// recvDatagram waits for the next datagram. Retaining the returned slice is safe:
// quic-go copies on the way in, both when parsing the frame and when queueing it.
//
// It reads with the connection's own context, so a connection that dies unblocks the
// mux's receive loop rather than leaving it parked forever.
func (t *Tunnel) recvDatagram() ([]byte, error) {
	return t.conn.ReceiveDatagram(t.conn.Context())
}

func (t *Tunnel) logFlowDrop(id uint32, reason string) {
	if !t.diagnostic {
		return
	}
	slog.Warn("tunnel_quic_flow_dropped", "flow", id, "reason", reason)
}

// muxDone reports when the mux's receive loop has stopped, or a closed channel when
// this tunnel has no mux. Used only by Close, which must not wait on a mux that was
// never built.
func (t *Tunnel) muxDone() <-chan struct{} {
	if t.mux == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return t.mux.Done()
}

// waitMuxDone blocks until the mux's receive loop has exited. The loop only unblocks
// when the QUIC connection ends, which Close has already arranged by the time this
// runs; ctx is a backstop so a wedged connection cannot hang shutdown.
func (t *Tunnel) waitMuxDone(ctx context.Context) {
	select {
	case <-t.muxDone():
	case <-ctx.Done():
	}
}
