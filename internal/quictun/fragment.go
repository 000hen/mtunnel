package quictun

import (
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"mtunnel-libp2p/internal/flowmux"
)

// A QUIC DATAGRAM is deliberately bounded by the path MTU. The flow mux carries
// complete UDP packets, however, so the boundary between the two preserves a mux
// message by fragmenting it here and reassembling it before handing it back.
const (
	datagramMagic   = 0x4d54 // "MT"
	datagramVersion = 1

	datagramHeaderSize      = 16
	datagramFragmentPayload = 1000

	// A flowmux message is its prefix plus the UDP forwarder's two-byte length
	// prefix and one legal UDP payload.
	// Keep the limit explicit so malformed peer input cannot make the reassembler
	// allocate according to an untrusted advertised size.
	maxUDPDatagram     = 2 + 65535
	maxDatagramMessage = flowmux.Header + maxUDPDatagram
	maxPartialMessages = 128
	maxPartialBytes    = 4 * maxDatagramMessage
	partialTTL         = 30 * time.Second
)

var errDatagramTooLarge = errors.New("quictun: datagram message exceeds UDP maximum")

type datagramCodec struct {
	send func([]byte) error
	recv func() ([]byte, error)

	mu sync.Mutex

	nextID   uint32
	partial  map[uint32]*partialDatagram
	reserved int
	closed   bool
}

type partialDatagram struct {
	created  time.Time
	total    int
	parts    [][]byte
	received int
}

func newDatagramCodec(send func([]byte) error, recv func() ([]byte, error)) *datagramCodec {
	return &datagramCodec{
		send:    send,
		recv:    recv,
		partial: make(map[uint32]*partialDatagram),
	}
}

func (c *datagramCodec) Send(message []byte) error {
	if len(message) > maxDatagramMessage {
		return errDatagramTooLarge
	}

	count := (len(message) + datagramFragmentPayload - 1) / datagramFragmentPayload
	if count == 0 {
		count = 1
	}

	c.mu.Lock()
	c.nextID++
	id := c.nextID
	c.mu.Unlock()

	for index := range count {
		start := index * datagramFragmentPayload
		end := min(start+datagramFragmentPayload, len(message))
		fragment := make([]byte, datagramHeaderSize+end-start)
		writeDatagramHeader(fragment, id, index, count, len(message))
		copy(fragment[datagramHeaderSize:], message[start:end])
		if err := c.send(fragment); err != nil {
			return err
		}
	}
	return nil
}

func (c *datagramCodec) Recv() ([]byte, error) {
	for {
		fragment, err := c.recv()
		if err != nil {
			return nil, err
		}
		if message := c.accept(fragment, time.Now()); message != nil {
			return message, nil
		}
	}
}

// Close releases incomplete messages immediately. Receive is unblocked by the QUIC
// connection's context, which the owner closes before calling this method.
func (c *datagramCodec) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	c.partial = nil
	c.reserved = 0
}

func (c *datagramCodec) accept(fragment []byte, now time.Time) []byte {
	if len(fragment) < datagramHeaderSize {
		return nil
	}
	if binary.BigEndian.Uint16(fragment[0:2]) != datagramMagic || fragment[2] != datagramVersion {
		return nil
	}

	id := binary.BigEndian.Uint32(fragment[4:8])
	index := int(binary.BigEndian.Uint16(fragment[8:10]))
	count := int(binary.BigEndian.Uint16(fragment[10:12]))
	total := int(binary.BigEndian.Uint32(fragment[12:16]))
	payload := fragment[datagramHeaderSize:]
	if !validFragment(index, count, total, len(payload)) {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.dropExpired(now)

	p := c.partial[id]
	if p == nil {
		c.reserve(total)
		if len(c.partial) >= maxPartialMessages || c.reserved+total > maxPartialBytes {
			return nil
		}
		p = &partialDatagram{
			created: now,
			total:   total,
			parts:   make([][]byte, count),
		}
		c.partial[id] = p
		c.reserved += total
	} else if p.total != total || len(p.parts) != count {
		// Reusing an in-flight ID with a different shape cannot be a valid duplicate.
		return nil
	}

	if p.parts[index] != nil {
		return nil // A duplicate fragment is intentionally idempotent.
	}
	p.parts[index] = append([]byte(nil), payload...)
	p.received++
	if p.received != len(p.parts) {
		return nil
	}

	message := make([]byte, 0, p.total)
	for _, part := range p.parts {
		message = append(message, part...)
	}
	c.remove(id, p)
	return message
}

func validFragment(index, count, total, payloadLen int) bool {
	if total < 0 || total > maxDatagramMessage || count < 1 || index < 0 || index >= count {
		return false
	}
	wantCount := (total + datagramFragmentPayload - 1) / datagramFragmentPayload
	if wantCount == 0 {
		wantCount = 1
	}
	if count != wantCount {
		return false
	}
	start := index * datagramFragmentPayload
	end := min(start+datagramFragmentPayload, total)
	return payloadLen == end-start
}

func (c *datagramCodec) reserve(total int) {
	for (len(c.partial) >= maxPartialMessages || c.reserved+total > maxPartialBytes) && len(c.partial) > 0 {
		var oldestID uint32
		var oldest *partialDatagram
		for id, p := range c.partial {
			if oldest == nil || p.created.Before(oldest.created) {
				oldestID, oldest = id, p
			}
		}
		c.remove(oldestID, oldest)
	}
}

func (c *datagramCodec) dropExpired(now time.Time) {
	for id, p := range c.partial {
		if now.Sub(p.created) >= partialTTL {
			c.remove(id, p)
		}
	}
}

func (c *datagramCodec) remove(id uint32, p *partialDatagram) {
	if c.partial[id] != p {
		return
	}
	delete(c.partial, id)
	c.reserved -= p.total
}

func writeDatagramHeader(dst []byte, id uint32, index, count, total int) {
	binary.BigEndian.PutUint16(dst[0:2], datagramMagic)
	dst[2] = datagramVersion
	binary.BigEndian.PutUint32(dst[4:8], id)
	binary.BigEndian.PutUint16(dst[8:10], uint16(index))
	binary.BigEndian.PutUint16(dst[10:12], uint16(count))
	binary.BigEndian.PutUint32(dst[12:16], uint32(total))
}
