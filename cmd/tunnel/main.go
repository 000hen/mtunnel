package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"mtunnel-libp2p/internal/control"
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
	directTimeout := flag.Duration("direct-timeout", 15*time.Second, "Time to wait for a direct stream before explicit relay fallback")
	relaysFlag := flag.String("relays", "", "Comma-separated dedicated relay multiaddresses ending in /p2p/<peer-id> (host only)")

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
	if *directTimeout <= 0 {
		log.Fatal("Direct timeout must be positive")
	}
	if *diagnostic {
		slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	}
	p2pConfig := p2p.Config{
		ConnectionMode:    connectionMode,
		Transport:         transportMode,
		DHTMode:           dhtMode,
		DirectDialTimeout: *directTimeout,
		Diagnostic:        *diagnostic,
	}
	if value := strings.TrimSpace(*relaysFlag); value != "" {
		for _, relay := range strings.Split(value, ",") {
			p2pConfig.RelayAddrs = append(p2pConfig.RelayAddrs, strings.TrimSpace(relay))
		}
	}

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

	if *diagnostic {
		slog.Info("test_configuration",
			"commit_sha", buildRevision(),
			"role", map[bool]string{true: "host", false: "client"}[*token == ""],
			"network", *network,
			"connection_mode", connectionMode,
			"transport", transportMode,
			"dht_mode", dhtMode,
			"direct_timeout_ms", directTimeout.Milliseconds(),
			"configured_relays", len(p2pConfig.RelayAddrs),
			"start_time", time.Now().UTC().Format(time.RFC3339Nano),
		)
	}
	opts := tunnel.Options{P2P: p2pConfig, Bandwidth: bandwidth}
	if *token == "" {
		err = tunnel.RunHost(ctx, h, emitter, *network, *port, opts)
	} else {
		err = tunnel.RunClient(ctx, h, emitter, *token, *port, opts)
	}
	if err != nil {
		fatal(emitter, "Tunnel exited with error", err)
	}
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
