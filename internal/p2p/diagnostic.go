package p2p

import (
	"context"
	"log/slog"
	"runtime"
	"strings"
	"time"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/metrics"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

var processStarted = time.Now()

// StreamEvent names how a tunnel stream came to exist. The three cases are not
// interchangeable in a diagnostic record: an opened data stream is this side
// dialing, an accepted one is the peer dialing, and a negotiate stream is neither
// side's data plane yet.
type StreamEvent string

const (
	StreamOpened          StreamEvent = "opened"
	StreamAccepted        StreamEvent = "accepted"
	StreamNegotiateOpened StreamEvent = "negotiate-opened"
)

// LogStreamPath records the immutable libp2p connection selected for a tunnel
// stream. Existing streams do not migrate when a better connection appears.
func LogStreamPath(event StreamEvent, stream network.Stream, enabled bool) {
	if !enabled {
		return
	}
	conn := stream.Conn()
	stat := conn.Stat()
	state := conn.ConnState()
	local := conn.LocalMultiaddr().String()
	remote := conn.RemoteMultiaddr().String()
	slog.Info("tunnel_stream_path",
		"event", string(event),
		"remote_peer", conn.RemotePeer().String(),
		"connection_id", conn.ID(),
		"limited", stat.Limited,
		"direct", !stat.Limited && !strings.Contains(local, "/p2p-circuit") && !strings.Contains(remote, "/p2p-circuit"),
		"transport", state.Transport,
		"stream_multiplexer", string(state.StreamMultiplexer),
		"security", string(state.Security),
		"local_multiaddr", local,
		"remote_multiaddr", remote,
		"p2p_circuit", strings.Contains(local, "/p2p-circuit") || strings.Contains(remote, "/p2p-circuit"),
		"process_uptime_ms", time.Since(processStarted).Milliseconds(),
		"connection_age_ms", time.Since(stat.Opened).Milliseconds(),
	)
}

// TierReporter names the data-plane tier currently carrying forwarded traffic. It
// is a function rather than a value because the tier outlives no single snapshot:
// a host serves peers on different tiers over its lifetime, and a client resolves
// its own only once negotiation finishes. Reporting nothing is legitimate - it
// means no forwarded connection is open - so an empty string is a valid answer and
// a nil reporter is treated as one.
type TierReporter func() string

// StartDiagnostics emits low-frequency JSON-friendly snapshots until ctx ends.
// A nil DHT records a routing-table size of zero, as in close-after-connect mode.
func StartDiagnostics(ctx context.Context, h host.Host, idht *dht.IpfsDHT, target peer.ID, bandwidth *metrics.BandwidthCounter, tier TierReporter) {
	emitDiagnostics(h, idht, target, bandwidth, tier)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			emitDiagnostics(h, idht, target, bandwidth, tier)
		}
	}
}

func emitDiagnostics(h host.Host, idht *dht.IpfsDHT, target peer.ID, bandwidth *metrics.BandwidthCounter, tier TierReporter) {
	connections := h.Network().Conns()
	streams := 0
	activeTransport := ""
	activeLimited := false
	for _, conn := range connections {
		connStreams := conn.GetStreams()
		streams += len(connStreams)
		for _, stream := range connStreams {
			if stream.Protocol() == ProtocolID {
				activeTransport = conn.ConnState().Transport
				activeLimited = conn.Stat().Limited
			}
		}
	}

	directToTarget, relayToTarget := 0, 0
	if target != "" {
		for _, conn := range h.Network().ConnsToPeer(target) {
			if conn.Stat().Limited || strings.Contains(conn.RemoteMultiaddr().String(), "/p2p-circuit") {
				relayToTarget++
			} else {
				directToTarget++
			}
			if len(conn.GetStreams()) > 0 {
				activeTransport = conn.ConnState().Transport
				activeLimited = conn.Stat().Limited
			}
		}
	}

	routingTableSize := 0
	if idht != nil {
		routingTableSize = idht.RoutingTable().Size()
	}
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	bytes := bandwidth.GetBandwidthTotals()

	activeTier := ""
	if tier != nil {
		activeTier = tier()
	}

	slog.Info("tunnel_diagnostics",
		"process_uptime_ms", time.Since(processStarted).Milliseconds(),
		"peers", len(h.Network().Peers()),
		"connections", len(connections),
		"streams", streams,
		"dht_routing_table_size", routingTableSize,
		"goroutines", runtime.NumGoroutine(),
		"heap_alloc_bytes", mem.HeapAlloc,
		"heap_sys_bytes", mem.HeapSys,
		"gc_cycles", mem.NumGC,
		"bytes_received", bytes.TotalIn,
		"bytes_sent", bytes.TotalOut,
		"receive_rate_bytes_per_sec", bytes.RateIn,
		"send_rate_bytes_per_sec", bytes.RateOut,
		"active_tunnel_transport", activeTransport,
		"active_connection_limited", activeLimited,
		// A separate axis from active_tunnel_transport, not a finer reading of it:
		// that key describes the libp2p connection carrying signalling, which keeps
		// running under a tier whose data plane never touches libp2p at all.
		"active_tunnel_tier", activeTier,
		"target_direct_connections", directToTarget,
		"target_relay_connections", relayToTarget,
	)
}
