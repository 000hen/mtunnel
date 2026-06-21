package main

import (
	"encoding/binary"
	"fmt"
	"io"
)

// maxDatagramSize is the largest UDP payload the tunnel forwards. 65535 is the
// maximum value the 2-byte length prefix can express and exceeds the 65507-byte
// maximum payload of a UDP/IPv4 datagram, so every valid datagram fits. Read
// buffers must be at least this large: a short read from a connected UDP socket
// silently truncates the datagram.
const maxDatagramSize = 65535

// writeDatagram frames payload as a single message on w: a 2-byte big-endian
// length prefix followed by the bytes. libp2p streams are reliable, ordered byte
// streams with no message boundaries, so the prefix lets the far end recover the
// original datagram boundaries. The whole frame is written in one call so a
// stream carrying one writer never desynchronises.
func writeDatagram(w io.Writer, payload []byte) error {
	if len(payload) > maxDatagramSize {
		return fmt.Errorf("datagram too large to forward: %d bytes", len(payload))
	}

	frame := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(payload)))
	copy(frame[2:], payload)

	_, err := w.Write(frame)
	return err
}

// readDatagram reads one frame written by writeDatagram into buf and returns the
// payload length. buf must be at least maxDatagramSize bytes.
func readDatagram(r io.Reader, buf []byte) (int, error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, err
	}

	n := int(binary.BigEndian.Uint16(header[:]))
	if n > len(buf) {
		return 0, fmt.Errorf("datagram length %d exceeds buffer of %d", n, len(buf))
	}

	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		return 0, err
	}
	return n, nil
}
