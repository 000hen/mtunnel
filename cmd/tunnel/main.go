package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"math"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"mtunnel-libp2p/internal/control"
	"mtunnel-libp2p/internal/nat"
	"mtunnel-libp2p/internal/p2p"
	"mtunnel-libp2p/internal/tunnel"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/metrics"
)

func main() {
	port := flag.Int("port", 0, "Port to forward, in client mode this is the local port to connect to")
	network := flag.String("network", "tcp", "Network type for the forwarded connection: tcp or udp")
	token := flag.String("token", "", "Connection token for client mode")
	diagnostic := flag.Bool("diagnostic", false, "Emit structured path, resource, and data-flow diagnostics")
	connectionModeFlag := flag.String("connection-mode", "direct-first", "Stream policy: direct-only, direct-first, or relay-only")
	transportFlag := flag.String("transport", "default", "libp2p transport: default, quic, tcp, or webrtc")
	dhtModeFlag := flag.String("dht-mode", "close-after-connect", "Client DHT lifecycle: close-after-connect, no-refresh, or current")
	tunnelModeFlag := flag.String("tunnel-mode", "auto", "Tunnel data-plane tier: auto (cascade wireguard -> quic -> libp2p), wireguard or quic (forced, no fallback), or libp2p (floor only)")
	directTimeout := flag.Duration("direct-timeout", 15*time.Second, "Time to wait for a direct stream before explicit relay fallback")
	relaysFlag := flag.String("relays", "", "Comma-separated dedicated relay multiaddresses ending in /p2p/<peer-id> (host only)")
	stunServersFlag := flag.String("stun-servers", "", "Comma-separated STUN server URLs for NAT traversal; empty uses the built-in public defaults")
	punchTimeout := flag.Duration("punch-timeout", nat.DefaultTimeout, "Time budget for the NAT hole punch's connectivity checks")
	punchGatherTimeout := flag.Duration("punch-gather-timeout", nat.DefaultGatherTimeout, "Time budget for NAT candidate gathering (STUN); shorter than -punch-timeout because a gather that will work finishes in well under a second")
	punchAttempts := flag.Uint("punch-attempts", uint(tunnel.DefaultPunchAttempts), "How many times to attempt the NAT hole punch before falling back to the libp2p relay; the effective count is the lower of the two peers'")
	handshakeTimeout := flag.Duration("handshake-timeout", tunnel.DefaultHandshakeTimeout, "Time budget for a tunnel tier's own handshake once the NAT punch has succeeded, before falling back")

	flag.Parse()

	emitter := control.NewEmitter(os.Stdout)

	if err := tunnel.NetworkSupported(*network); err != nil {
		log.Fatalf("Invalid network type: %v", err)
	}

	if *port < 0 {
		log.Fatalf("Port must be a non-negative integer")
	}

	if *token == "" && *port == 0 {
		log.Fatalf("Host mode requires a non-zero port to forward")
	}
	connectionMode, err := p2p.ParseConnectionMode(*connectionModeFlag)
	if err != nil {
		log.Fatal(err)
	}
	transportMode, err := p2p.ParseTransportMode(*transportFlag)
	if err != nil {
		log.Fatal(err)
	}
	dhtMode, err := p2p.ParseDHTMode(*dhtModeFlag)
	if err != nil {
		log.Fatal(err)
	}
	tunnelMode, err := p2p.ParseTunnelMode(*tunnelModeFlag)
	if err != nil {
		log.Fatal(err)
	}
	if *directTimeout <= 0 {
		log.Fatal("Direct timeout must be positive")
	}
	if *punchTimeout <= 0 {
		log.Fatal("Punch timeout must be positive")
	}
	if *punchGatherTimeout <= 0 {
		log.Fatal("Punch gather timeout must be positive")
	}
	// Capped at the wire type's range rather than at some policy maximum: the count is
	// advertised as a uint8 in the Hello, so anything above 255 could not be sent, and
	// silently truncating it would give the peer a different number than the one asked
	// for - which is the one thing the lockstep retry cannot survive.
	if *punchAttempts < 1 || *punchAttempts > math.MaxUint8 {
		log.Fatalf("Punch attempts must be between 1 and %d", math.MaxUint8)
	}
	if *handshakeTimeout <= 0 {
		log.Fatal("Handshake timeout must be positive")
	}
	if *diagnostic {
		// Debug level, not the handler default: the tunnel tiers narrate at that
		// level on purpose, because wireguard-go logs a line per handshake and per
		// keepalive and that volume only belongs in a diagnostic run. Leaving the
		// handler at Info would discard exactly the packet-level detail this flag
		// exists to produce.
		slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}
	p2pConfig := p2p.Config{
		ConnectionMode:    connectionMode,
		Transport:         transportMode,
		DHTMode:           dhtMode,
		TunnelMode:        tunnelMode,
		DirectDialTimeout: *directTimeout,
		Diagnostic:        *diagnostic,
	}
	p2pConfig.RelayAddrs = splitList(*relaysFlag)

	// A single, signal-aware root context drives shutdown for both roles: it is
	// cancelled on the first interrupt/termination signal and can also be cancelled
	// from within (e.g. a stdin SHUTDOWN action).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var h host.Host
	var bandwidth *metrics.BandwidthCounter
	if *token == "" {
		h, bandwidth, err = p2p.NewServerHost(p2pConfig)
	} else {
		h, bandwidth, err = p2p.NewClientHost(p2pConfig)
	}
	if err != nil {
		fatal(emitter, "Failed to initialize peer", err)
	}

	opts := tunnel.Options{
		P2P:                p2pConfig,
		Bandwidth:          bandwidth,
		STUNServers:        splitList(*stunServersFlag),
		PunchTimeout:       *punchTimeout,
		PunchGatherTimeout: *punchGatherTimeout,
		PunchAttempts:      uint8(*punchAttempts),
		HandshakeTimeout:   *handshakeTimeout,
	}

	if *diagnostic {
		role := "client"
		if *token == "" {
			role = "host"
		}
		slog.Info("test_configuration",
			"commit_sha", buildRevision(),
			"role", role,
			"network", *network,
			"connection_mode", connectionMode,
			"transport", transportMode,
			"dht_mode", dhtMode,
			"tunnel_mode", tunnelMode,
			"direct_timeout_ms", directTimeout.Milliseconds(),
			"punch_timeout_ms", punchTimeout.Milliseconds(),
			"punch_gather_timeout_ms", punchGatherTimeout.Milliseconds(),
			"punch_attempts", *punchAttempts,
			"handshake_timeout_ms", handshakeTimeout.Milliseconds(),
			"configured_relays", len(p2pConfig.RelayAddrs),
			"configured_stun_servers", len(opts.STUNServers),
			"start_time", time.Now().UTC().Format(time.RFC3339Nano),
		)
	}
	if *token == "" {
		err = tunnel.RunHost(ctx, h, emitter, *network, *port, opts)
	} else {
		err = tunnel.RunClient(ctx, h, emitter, *token, *port, opts)
	}
	if err != nil {
		fatal(emitter, "Tunnel exited with error", err)
	}
}

// splitList parses a comma-separated flag value into its trimmed, non-empty
// entries. It returns nil for an empty value, which every consumer reads as "not
// configured" and answers with its own default - so passing the flag with an empty
// value is the same as omitting it.
func splitList(value string) []string {
	var out []string
	for entry := range strings.SplitSeq(value, ",") {
		if entry = strings.TrimSpace(entry); entry != "" {
			out = append(out, entry)
		}
	}
	return out
}

func buildRevision() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, setting := range info.Settings {
		if setting.Key == "vcs.revision" {
			return setting.Value
		}
	}
	return "unknown"
}

// fatal reports an error both as a JSON event (so a supervising process can see it)
// and on the standard logger, then terminates the process.
func fatal(emitter *control.Emitter, msg string, err error) {
	emitter.Emit(control.Output{
		Action: control.ERROR,
		Error:  fmt.Sprintf("%s: %v", msg, err),
	})
	log.Fatalf("%s: %v", msg, err)
}
