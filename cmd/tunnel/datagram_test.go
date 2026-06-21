package main

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestDatagramRoundTrip(t *testing.T) {
	cases := map[string][]byte{
		"empty":    {},
		"small":    []byte("hello udp"),
		"max size": bytes.Repeat([]byte{0xAB}, maxDatagramSize),
	}

	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := writeDatagram(&buf, payload); err != nil {
				t.Fatalf("writeDatagram: %v", err)
			}

			out := make([]byte, maxDatagramSize)
			n, err := readDatagram(&buf, out)
			if err != nil {
				t.Fatalf("readDatagram: %v", err)
			}
			if !bytes.Equal(out[:n], payload) {
				t.Fatalf("round trip mismatch: got %d bytes, want %d", n, len(payload))
			}
			if buf.Len() != 0 {
				t.Fatalf("expected stream fully consumed, %d bytes left", buf.Len())
			}
		})
	}
}

func TestDatagramFramingPreservesBoundaries(t *testing.T) {
	payloads := [][]byte{[]byte("first"), {}, []byte("third datagram"), {0x00, 0x01, 0x02}}

	var buf bytes.Buffer
	for _, p := range payloads {
		if err := writeDatagram(&buf, p); err != nil {
			t.Fatalf("writeDatagram: %v", err)
		}
	}

	out := make([]byte, maxDatagramSize)
	for i, want := range payloads {
		n, err := readDatagram(&buf, out)
		if err != nil {
			t.Fatalf("readDatagram #%d: %v", i, err)
		}
		if !bytes.Equal(out[:n], want) {
			t.Fatalf("datagram #%d mismatch: got %q, want %q", i, out[:n], want)
		}
	}
}

func TestWriteDatagramTooLarge(t *testing.T) {
	var buf bytes.Buffer
	if err := writeDatagram(&buf, make([]byte, maxDatagramSize+1)); err == nil {
		t.Fatal("expected error for oversized datagram, got nil")
	}
	if buf.Len() != 0 {
		t.Fatalf("expected nothing written on error, got %d bytes", buf.Len())
	}
}

func TestReadDatagramShortBuffer(t *testing.T) {
	var buf bytes.Buffer
	if err := writeDatagram(&buf, []byte("0123456789")); err != nil {
		t.Fatalf("writeDatagram: %v", err)
	}

	if _, err := readDatagram(&buf, make([]byte, 5)); err == nil {
		t.Fatal("expected error reading into undersized buffer, got nil")
	}
}

func TestReadDatagramTruncatedStream(t *testing.T) {
	// A 2-byte header announcing 10 bytes, but only 3 bytes of payload follow.
	truncated := []byte{0x00, 0x0A, 0x01, 0x02, 0x03}

	_, err := readDatagram(bytes.NewReader(truncated), make([]byte, maxDatagramSize))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected io.ErrUnexpectedEOF, got %v", err)
	}
}
