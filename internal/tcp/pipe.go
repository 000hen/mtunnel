package tcp

import (
	"errors"
	"io"
	"log"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// pipe streams data bidirectionally between a and b until both directions reach
// EOF or error. Each direction is half-closed once its source is drained so the
// peer observes a clean EOF; if half-close is unsupported the side is closed
// outright.
func pipe(a, b io.ReadWriteCloser, diagnostic bool) {
	var wg sync.WaitGroup

	wg.Go(func() {
		copyAndCloseWrite(a, b, diagnostic, "local_to_tunnel")
	})

	wg.Go(func() {
		copyAndCloseWrite(b, a, diagnostic, "tunnel_to_local")
	})

	wg.Wait()
}

// copyAndCloseWrite copies src into dst, then signals end-of-stream on dst by
// half-closing the write side (falling back to a full close).
func copyAndCloseWrite(dst, src io.ReadWriteCloser, diagnostic bool, direction string) {
	var err error
	if diagnostic {
		err = copyWithDiagnostics(dst, src, direction)
	} else {
		_, err = io.Copy(dst, src)
	}
	if err != nil && !isBenignForwardErr(err) {
		log.Printf("Forwarding error: %v", err)
	}

	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	} else {
		_ = dst.Close()
	}
}

type copyProgress struct {
	bytes     atomic.Int64
	lastRead  atomic.Int64
	lastWrite atomic.Int64
}

func copyWithDiagnostics(dst io.Writer, src io.Reader, direction string) error {
	progress := &copyProgress{}
	now := time.Now().UnixNano()
	progress.lastRead.Store(now)
	progress.lastWrite.Store(now)
	done := make(chan struct{})
	go reportCopyProgress(done, progress, direction)
	defer close(done)

	buf := make([]byte, 32*1024)
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			progress.lastRead.Store(time.Now().UnixNano())
			written := 0
			for written < n {
				started := time.Now()
				nw, writeErr := dst.Write(buf[written:n])
				duration := time.Since(started)
				if duration >= 250*time.Millisecond {
					slog.Warn("tunnel_blocked_write", "direction", direction, "duration_ms", duration.Milliseconds(), "bytes", nw)
				}
				if nw > 0 {
					written += nw
					progress.bytes.Add(int64(nw))
					progress.lastWrite.Store(time.Now().UnixNano())
				}
				if writeErr != nil {
					return writeErr
				}
				if nw == 0 {
					return io.ErrShortWrite
				}
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return readErr
		}
	}
}

func reportCopyProgress(done <-chan struct{}, progress *copyProgress, direction string) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case now := <-ticker.C:
			slog.Info("tunnel_copy_progress",
				"direction", direction,
				"bytes", progress.bytes.Load(),
				"since_last_read_ms", now.Sub(time.Unix(0, progress.lastRead.Load())).Milliseconds(),
				"since_last_write_ms", now.Sub(time.Unix(0, progress.lastWrite.Load())).Milliseconds(),
			)
		}
	}
}

// isBenignForwardErr reports whether a forwarding error is the expected result of
// either side closing the connection during normal operation or shutdown, and
// therefore not worth logging.
func isBenignForwardErr(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe)
}
