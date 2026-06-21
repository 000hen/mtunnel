package udp

import (
	"context"
	"errors"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"mtunnel-libp2p/internal/transport"
)

// flowIdleTimeout bounds how long a UDP flow (one client source address and its
// dedicated tunnel stream) is kept alive without traffic. UDP has no connection
// close, so idle flows are reaped to release their stream and goroutines.
const flowIdleTimeout = 60 * time.Second

// serveLocal forwards datagrams between a local UDP socket and the host. UDP is
// connectionless, so the single socket receives traffic from many remote
// addresses; each distinct source address is mapped to its own tunnel stream (a
// "flow") so the host can dial and reply to it independently, mirroring the
// one-stream-per-connection model used for TCP. It returns once the socket is
// closed and every flow has drained.
func serveLocal(ctx context.Context, opener transport.Opener, conn *net.UDPConn) {
	flows := newFlowTable(opener, conn)
	defer flows.closeAll()

	flows.wg.Go(func() { flows.reap(ctx) })

	buf := make([]byte, maxDatagramSize)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				log.Println("Local UDP socket closed, no longer forwarding datagrams")
				return
			}
			log.Printf("Failed to read from local UDP socket: %v", err)
			continue
		}

		flow, err := flows.get(ctx, addr)
		if err != nil {
			log.Printf("Failed to open tunnel stream for %s: %v", addr, err)
			continue
		}

		if err := writeDatagram(flow.stream, buf[:n]); err != nil {
			log.Printf("Failed to forward datagram from %s: %v", addr, err)
			flows.remove(flow)
		}
	}
}

// flow is a single client source address and the tunnel stream that carries its
// datagrams in both directions.
type flow struct {
	stream transport.Stream
	addr   net.Addr
	// lastActivity is the UnixNano timestamp of the most recent datagram in either
	// direction, used by the reaper to expire idle flows.
	lastActivity atomic.Int64
}

func (f *flow) touch() {
	f.lastActivity.Store(time.Now().UnixNano())
}

// flowTable tracks the live UDP flows for one local socket. Idle flows are
// expired by a reaper goroutine that serveLocal starts; closeAll stops the
// reaper, tears down every flow, and waits for their goroutines.
type flowTable struct {
	opener transport.Opener
	conn   *net.UDPConn

	mu     sync.Mutex
	flows  map[string]*flow
	closed bool

	done chan struct{}  // closed by closeAll to stop the reaper
	wg   sync.WaitGroup // reverse pumps + reaper
}

func newFlowTable(opener transport.Opener, conn *net.UDPConn) *flowTable {
	return &flowTable{
		opener: opener,
		conn:   conn,
		flows:  make(map[string]*flow),
		done:   make(chan struct{}),
	}
}

// get returns the flow for addr, opening a tunnel stream and starting its reverse
// pump on first use. The flow is touched under the lock so a concurrent reaper
// cannot expire it between lookup and the caller's write.
//
// Only serveLocal's single read loop calls get, so holding the lock across
// OpenStream cannot block a competing get - it only briefly delays the reaper.
// OpenStream is fast in the common case (the client is already connected to the
// host), and ctx is cancelled on shutdown to unblock it.
func (t *flowTable) get(ctx context.Context, addr net.Addr) (*flow, error) {
	key := addr.String()

	t.mu.Lock()
	defer t.mu.Unlock()

	if f, ok := t.flows[key]; ok {
		f.touch()
		return f, nil
	}

	if t.closed {
		return nil, errors.New("udp forwarder is shutting down")
	}

	stream, err := t.opener.OpenStream(ctx)
	if err != nil {
		return nil, err
	}

	f := &flow{stream: stream, addr: addr}
	f.touch()
	t.flows[key] = f
	log.Printf("Opened UDP flow for %s", addr)

	t.wg.Go(func() {
		t.pumpStreamToLocal(f)
	})

	return f, nil
}

// pumpStreamToLocal copies datagrams arriving on the flow's stream back to the
// originating UDP client. It returns when the stream ends, removing the flow.
func (t *flowTable) pumpStreamToLocal(f *flow) {
	defer t.remove(f)

	buf := make([]byte, maxDatagramSize)
	for {
		n, err := readDatagram(f.stream, buf)
		if err != nil {
			return
		}

		f.touch()
		if _, err := t.conn.WriteTo(buf[:n], f.addr); err != nil {
			if !errors.Is(err, net.ErrClosed) {
				log.Printf("Failed to write datagram to %s: %v", f.addr, err)
			}
			return
		}
	}
}

// remove drops f and resets its stream, but only if f is still the flow
// registered for its address. The identity check matters because a reverse pump
// can run this (via its defer) after its flow was already reaped and a new flow
// was registered under the same source address; keying on the address alone, the
// stale pump would evict and reset the live replacement. It is idempotent, so the
// forward path and the reverse pump can both call it for the same flow.
func (t *flowTable) remove(f *flow) {
	key := f.addr.String()

	t.mu.Lock()
	if t.flows[key] != f {
		t.mu.Unlock()
		return
	}
	delete(t.flows, key)
	t.mu.Unlock()

	f.stream.Reset()
}

// reap periodically expires flows that have seen no traffic within
// flowIdleTimeout, releasing their stream and reverse-pump goroutine. UDP has no
// connection close, so without this a transient client would leak a flow. It
// returns when ctx is cancelled or closeAll signals shutdown.
func (t *flowTable) reap(ctx context.Context) {
	ticker := time.NewTicker(flowIdleTimeout / 2)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.done:
			return
		case <-ticker.C:
			t.removeIdle()
		}
	}
}

func (t *flowTable) removeIdle() {
	cutoff := time.Now().Add(-flowIdleTimeout).UnixNano()

	t.mu.Lock()
	var idle []*flow
	for key, f := range t.flows {
		if f.lastActivity.Load() < cutoff {
			delete(t.flows, key)
			idle = append(idle, f)
		}
	}
	t.mu.Unlock()

	for _, f := range idle {
		log.Printf("Closing idle UDP flow for %s", f.addr)
		f.stream.Reset()
	}
}

// closeAll stops the reaper, resets every remaining flow, and waits for all
// reverse pumps to finish. The closed flag (set under the lock) stops get from
// starting new pumps, so the final Wait cannot race a late Add. Streams are reset
// outside the lock so the pumps' own remove calls do not deadlock against it.
func (t *flowTable) closeAll() {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	close(t.done)

	remaining := make([]*flow, 0, len(t.flows))
	for _, f := range t.flows {
		remaining = append(remaining, f)
	}
	t.flows = make(map[string]*flow)
	t.mu.Unlock()

	for _, f := range remaining {
		f.stream.Reset()
	}

	t.wg.Wait()
}
