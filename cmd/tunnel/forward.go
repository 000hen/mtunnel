package main

import (
	"errors"
	"io"
	"log"
	"net"
	"sync"
)

// pipe streams data bidirectionally between a and b until both directions reach
// EOF or error. Each direction is half-closed once its source is drained so the
// peer observes a clean EOF; if half-close is unsupported the side is closed
// outright.
func pipe(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup

	wg.Go(func() {
		copyAndCloseWrite(a, b)
	})

	wg.Go(func() {
		copyAndCloseWrite(b, a)
	})

	wg.Wait()
}

// copyAndCloseWrite copies src into dst, then signals end-of-stream on dst by
// half-closing the write side (falling back to a full close).
func copyAndCloseWrite(dst, src io.ReadWriteCloser) {
	if _, err := io.Copy(dst, src); err != nil && !isBenignForwardErr(err) {
		log.Printf("Forwarding error: %v", err)
	}

	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	} else {
		_ = dst.Close()
	}
}

// isBenignForwardErr reports whether a forwarding error is the expected result
// of either side closing the connection during normal operation or shutdown,
// and therefore not worth logging.
func isBenignForwardErr(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe)
}
