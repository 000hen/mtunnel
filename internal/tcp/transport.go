package tcp

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"

	"mtunnel-libp2p/internal/transport"
)

// Transport forwards a TCP service: each local connection rides a dedicated
// tunnel stream as a raw byte copy.
type Transport struct{}

// New returns a TCP transport.
func New() Transport { return Transport{} }

// Network returns the canonical network name.
func (Transport) Network() string { return "tcp" }

// Forward bridges an inbound tunnel stream and the host's local TCP connection.
func (Transport) Forward(s transport.Stream, local net.Conn) { pipe(s, local) }

// Listen opens the client's local TCP listener on localPort and returns a
// Forwarder that bridges each accepted connection to the host over a tunnel
// stream from opener.
func (Transport) Listen(ctx context.Context, opener transport.Opener, localPort int) (*transport.Forwarder, error) {
	listen, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", localPort))
	if err != nil {
		return nil, err
	}

	serve := func() { acceptLocalConns(ctx, opener, listen) }
	return transport.NewForwarder(listen.Addr(), serve, listen.Close), nil
}

// acceptLocalConns accepts connections on the local listener and forwards each
// one over a dedicated tunnel stream, returning once the listener is closed and
// all in-flight connections have finished.
func acceptLocalConns(ctx context.Context, opener transport.Opener, listen net.Listener) {
	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		localConn, err := listen.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				log.Println("Local listener closed, no longer accepting connections")
				return
			}

			log.Printf("Failed to accept local connection: %v", err)
			continue
		}

		wg.Go(func() {
			handleLocalConn(ctx, opener, localConn)
		})
	}
}

// handleLocalConn opens a tunnel stream and pipes the local connection through it
// until either side closes.
func handleLocalConn(ctx context.Context, opener transport.Opener, conn net.Conn) {
	defer conn.Close()

	s, err := opener.OpenStream(ctx)
	if err != nil {
		log.Printf("Failed to open tunnel stream: %v", err)
		return
	}
	defer s.Close()

	log.Println("Opened tunnel stream")
	pipe(s, conn)
	log.Println("Closed tunnel stream")
}
