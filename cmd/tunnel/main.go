package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"mtunnel-libp2p/internal/control"
	"mtunnel-libp2p/internal/p2p"
	"mtunnel-libp2p/internal/tunnel"
)

func main() {
	port := flag.Int("port", 0, "Port to forward, in client mode this is the local port to connect to")
	network := flag.String("network", "tcp", "Network type for the forwarded connection: tcp or udp")
	token := flag.String("token", "", "Connection token for client mode")

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

	// A single, signal-aware root context drives shutdown for both roles: it is
	// cancelled on the first interrupt/termination signal and can also be cancelled
	// from within (e.g. a stdin SHUTDOWN action).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	h, err := p2p.New()
	if err != nil {
		fatal(emitter, "Failed to initialize peer", err)
	}

	if *token == "" {
		err = tunnel.RunHost(ctx, h, emitter, *network, *port)
	} else {
		err = tunnel.RunClient(ctx, h, emitter, *token, *port)
	}
	if err != nil {
		fatal(emitter, "Tunnel exited with error", err)
	}
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
