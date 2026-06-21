package main

import (
	"context"
	"errors"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// serveLocalUDP forwards datagrams between a local UDP socket and the host. UDP
// is connectionless, so the single socket receives traffic from many remote
// addresses; each distinct source address is mapped to its own tunnel stream (a
// "flow") so the host can dial and reply to it independently, mirroring the
// one-stream-per-connection model used for TCP. It returns once the socket is
// closed and every flow has drained.
func serveLocalUDP(ctx context.Context, h host.Host, target peer.ID, conn *net.UDPConn) {
	flows := newUDPFlowTable(h, target, conn)
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
			flows.remove(addr)
		}
	}
}

// udpFlow is a single client source address and the tunnel stream that carries
// its datagrams in both directions.
type udpFlow struct {
	stream network.Stream
	addr   net.Addr
	// lastActivity is the UnixNano timestamp of the most recent datagram in
	// either direction, used by the reaper to expire idle flows.
	lastActivity atomic.Int64
}

func (f *udpFlow) touch() {
	f.lastActivity.Store(time.Now().UnixNano())
}

// udpFlowTable tracks the live UDP flows for one local socket. Idle flows are
// expired by a reaper goroutine that serveLocalUDP starts; closeAll stops the
// reaper, tears down every flow, and waits for their goroutines.
type udpFlowTable struct {
	h      host.Host
	target peer.ID
	conn   *net.UDPConn

	mu     sync.Mutex
	flows  map[string]*udpFlow
	closed bool

	done chan struct{}  // closed by closeAll to stop the reaper
	wg   sync.WaitGroup // reverse pumps + reaper
}

func newUDPFlowTable(h host.Host, target peer.ID, conn *net.UDPConn) *udpFlowTable {
	return &udpFlowTable{
		h:      h,
		target: target,
		conn:   conn,
		flows:  make(map[string]*udpFlow),
		done:   make(chan struct{}),
	}
}

// get returns the flow for addr, opening a tunnel stream and starting its
// reverse pump on first use. The flow is touched under the lock so a concurrent
// reaper cannot expire it between lookup and the caller's write.
//
// Only serveLocalUDP's single read loop calls get, so holding the lock across
// NewStream cannot block a competing get - it only briefly delays the reaper.
// NewStream is fast in the common case (the client is already connected to the
// host), and ctx is cancelled on shutdown to unblock it.
func (t *udpFlowTable) get(ctx context.Context, addr net.Addr) (*udpFlow, error) {
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

	stream, err := openTunnelStream(ctx, t.h, t.target)
	if err != nil {
		return nil, err
	}

	f := &udpFlow{stream: stream, addr: addr}
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
func (t *udpFlowTable) pumpStreamToLocal(f *udpFlow) {
	defer t.remove(f.addr)

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

// remove drops a flow and resets its stream. It is idempotent, so the reaper,
// the forward path, and the reverse pump can all call it for the same flow.
func (t *udpFlowTable) remove(addr net.Addr) {
	key := addr.String()

	t.mu.Lock()
	f, ok := t.flows[key]
	if ok {
		delete(t.flows, key)
	}
	t.mu.Unlock()

	if ok {
		f.stream.Reset()
	}
}

// reap periodically expires flows that have seen no traffic within
// udpFlowIdleTimeout, releasing their stream and reverse-pump goroutine. UDP has
// no connection close, so without this a transient client would leak a flow. It
// returns when ctx is cancelled or closeAll signals shutdown.
func (t *udpFlowTable) reap(ctx context.Context) {
	ticker := time.NewTicker(udpFlowIdleTimeout / 2)
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

func (t *udpFlowTable) removeIdle() {
	cutoff := time.Now().Add(-udpFlowIdleTimeout).UnixNano()

	t.mu.Lock()
	var idle []*udpFlow
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
func (t *udpFlowTable) closeAll() {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	close(t.done)

	remaining := make([]*udpFlow, 0, len(t.flows))
	for _, f := range t.flows {
		remaining = append(remaining, f)
	}
	t.flows = make(map[string]*udpFlow)
	t.mu.Unlock()

	for _, f := range remaining {
		f.stream.Reset()
	}

	t.wg.Wait()
}

// pipeDatagrams forwards datagrams in both directions between a tunnel stream and
// a connected UDP socket on the host side. Unlike pipe (which streams raw bytes
// for TCP), each direction preserves datagram boundaries via the length-prefix
// framing. It returns once either side fails; closing one endpoint unblocks the
// other (a connected UDP socket never reaches EOF on its own).
func pipeDatagrams(s network.Stream, conn net.Conn) {
	var wg sync.WaitGroup

	wg.Go(func() {
		// stream -> local UDP service
		buf := make([]byte, maxDatagramSize)
		for {
			n, err := readDatagram(s, buf)
			if err != nil {
				break
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				break
			}
		}
		_ = conn.Close()
	})

	wg.Go(func() {
		// local UDP service -> stream
		buf := make([]byte, maxDatagramSize)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				break
			}
			if err := writeDatagram(s, buf[:n]); err != nil {
				break
			}
		}
		_ = s.Reset()
	})

	wg.Wait()
}
