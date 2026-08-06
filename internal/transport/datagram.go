package transport

import "sync"

// NewDatagramStream adapts a message-oriented substrate - one recv call yields
// exactly one message, one send call transmits exactly one - to the byte-stream
// contract Stream requires.
//
// The tiers below the libp2p floor do not all hand back byte streams. A netstack UDP
// conn and a QUIC DATAGRAM flow are both message-oriented, and internal/udp's framing
// reads its 2-byte length prefix and payload as two sequential io.ReadFull calls.
// Pointed straight at a message substrate that second ReadFull would consume a whole
// separate datagram, so the framing has to ride on something that remembers where the
// last message left off. That is all this type is: it buffers the unread tail of the
// current message across Read calls, which lets internal/udp's already-tested framing
// work unchanged on top of any tier.
//
// It is the mirror image of the deadline-honouring conn in internal/nat, which keeps
// datagram semantics deliberately - truncating a short read, exactly as a UDP socket
// does - because its consumers are protocol engines that expect a packet interface.
// Here the consumer expects a stream, so nothing may be dropped.
//
// Read and Write may run on separate goroutines, which is how both forwarders drive a
// stream; neither is safe to call concurrently with itself. Close is safe from any
// goroutine, but releasing a Read already blocked inside recv is the substrate's job:
// closeFn must make the in-flight recv return.
func NewDatagramStream(recv func() ([]byte, error), send func([]byte) error, closeFn func() error) Stream {
	return &datagramStream{recv: recv, send: send, closeFn: closeFn}
}

type datagramStream struct {
	recv    func() ([]byte, error)
	send    func([]byte) error
	closeFn func() error

	// pending is the unread tail of the last message and err the recv failure that
	// ended the stream. Both belong to the reading goroutine alone.
	pending []byte
	err     error

	closeOnce sync.Once
	closeErr  error
}

var _ Stream = (*datagramStream)(nil)

// Read fills p from the current message, fetching the next one when it runs out. A
// message never spans a Read boundary in the other direction: p is filled at most to
// the end of the current message, so a caller asking for more than the message holds
// gets a short read rather than two messages spliced together.
func (d *datagramStream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	for len(d.pending) == 0 {
		if d.err != nil {
			// Sticky: a substrate that failed once must keep reporting it rather
			// than call recv again on a dead conn.
			return 0, d.err
		}
		msg, err := d.recv()
		if err != nil {
			d.err = err
			return 0, err
		}
		// An empty message carries nothing, and returning (0, nil) would look like a
		// no-progress read to io.ReadFull. Wait for one with content instead.
		d.pending = msg
	}

	n := copy(p, d.pending)
	d.pending = d.pending[n:]
	return n, nil
}

// Write transmits p as exactly one message. Callers must therefore write whole
// frames in single calls - internal/udp's writeDatagram already does, which is what
// makes its framing safe to run over a message substrate.
func (d *datagramStream) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := d.send(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close releases the substrate once, however many times it is called, and reports the
// same result each time.
func (d *datagramStream) Close() error {
	d.closeOnce.Do(func() {
		if d.closeFn != nil {
			d.closeErr = d.closeFn()
		}
	})
	return d.closeErr
}

// Reset maps onto Close, for the reason given on ConnStream: a datagram substrate has
// no abort primitive distinct from ending the flow.
func (d *datagramStream) Reset() error { return d.Close() }
