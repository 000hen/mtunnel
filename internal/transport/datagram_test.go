package transport

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// fakeSubstrate is a message-oriented source and sink: recv pops one queued message
// per call, send appends one. It is deliberately strict about the 1:1 message
// mapping, since that is the property the adapter exists to bridge.
type fakeSubstrate struct {
	inbox    [][]byte
	recvErr  error
	recvs    int
	sent     [][]byte
	sendErr  error
	closals  int
	closeErr error
}

func (f *fakeSubstrate) recv() ([]byte, error) {
	f.recvs++
	if len(f.inbox) == 0 {
		if f.recvErr != nil {
			return nil, f.recvErr
		}
		return nil, io.EOF
	}
	msg := f.inbox[0]
	f.inbox = f.inbox[1:]
	return msg, nil
}

func (f *fakeSubstrate) send(p []byte) error {
	if f.sendErr != nil {
		return f.sendErr
	}
	f.sent = append(f.sent, bytes.Clone(p))
	return nil
}

func (f *fakeSubstrate) close() error {
	f.closals++
	return f.closeErr
}

func (f *fakeSubstrate) stream() Stream { return NewDatagramStream(f.recv, f.send, f.close) }

func messages(sizes ...int) [][]byte {
	out := make([][]byte, 0, len(sizes))
	fill := byte('A')
	for _, size := range sizes {
		out = append(out, bytes.Repeat([]byte{fill}, size))
		fill++
	}
	return out
}

// Whatever the message sizes and however small the caller's buffer, every byte comes
// back in order and none are spliced across message boundaries.
func TestDatagramStreamReassembles(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		sizes  []int
		bufLen int
	}{
		"buffer larger than message":  {sizes: []int{10, 3, 7}, bufLen: 64},
		"buffer smaller than message": {sizes: []int{10, 3, 7}, bufLen: 4},
		"single-byte buffer":          {sizes: []int{5, 1, 9}, bufLen: 1},
		"one large message":           {sizes: []int{65535}, bufLen: 1500},
		"single byte messages":        {sizes: []int{1, 1, 1}, bufLen: 8},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			msgs := messages(tc.sizes...)
			want := bytes.Join(msgs, nil)
			sub := &fakeSubstrate{inbox: msgs}
			s := sub.stream()

			got := make([]byte, 0, len(want))
			buf := make([]byte, tc.bufLen)
			for {
				n, err := s.Read(buf)
				got = append(got, buf[:n]...)
				if err != nil {
					if !errors.Is(err, io.EOF) {
						t.Fatalf("Read: %v", err)
					}
					break
				}
				if n == 0 {
					t.Fatal("Read returned 0 bytes and no error, which io.ReadFull reads as no progress")
				}
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("reassembled %d bytes, want %d", len(got), len(want))
			}
		})
	}
}

// The case the adapter exists for: internal/udp's framing reads a 2-byte length
// prefix and then the payload as two sequential io.ReadFull calls. Against a raw
// message substrate the second call would eat the following datagram whole; through
// the adapter it must consume the tail of the current message instead.
func TestDatagramStreamCarriesLengthPrefixedFraming(t *testing.T) {
	t.Parallel()

	payloads := [][]byte{[]byte("first"), []byte("second-datagram"), {}, bytes.Repeat([]byte{0xAB}, 1200)}
	frames := make([][]byte, 0, len(payloads))
	for _, p := range payloads {
		frame := make([]byte, 2+len(p))
		binary.BigEndian.PutUint16(frame[:2], uint16(len(p)))
		copy(frame[2:], p)
		frames = append(frames, frame)
	}

	sub := &fakeSubstrate{inbox: frames}
	s := sub.stream()

	for i, want := range payloads {
		var header [2]byte
		if _, err := io.ReadFull(s, header[:]); err != nil {
			t.Fatalf("frame %d: read header: %v", i, err)
		}
		got := make([]byte, binary.BigEndian.Uint16(header[:]))
		if _, err := io.ReadFull(s, got); err != nil {
			t.Fatalf("frame %d: read payload: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("frame %d: payload = %d bytes, want %d", i, len(got), len(want))
		}
	}
}

// A read shorter than the current message keeps the tail; it must not fall through to
// the next message, which is how a naive truncating adapter silently drops data.
func TestDatagramStreamShortReadKeepsRemainder(t *testing.T) {
	t.Parallel()

	sub := &fakeSubstrate{inbox: [][]byte{[]byte("0123456789"), []byte("next")}}
	s := sub.stream()

	buf := make([]byte, 4)
	n, err := s.Read(buf)
	if err != nil || string(buf[:n]) != "0123" {
		t.Fatalf("first Read = %q, %v; want %q, nil", buf[:n], err, "0123")
	}
	if sub.recvs != 1 {
		t.Fatalf("recv called %d times for one message", sub.recvs)
	}

	rest := make([]byte, 64)
	n, err = s.Read(rest)
	if err != nil || string(rest[:n]) != "456789" {
		t.Fatalf("second Read = %q, %v; want %q, nil", rest[:n], err, "456789")
	}
	if sub.recvs != 1 {
		t.Fatalf("recv called %d times while the first message still had a tail", sub.recvs)
	}

	n, err = s.Read(rest)
	if err != nil || string(rest[:n]) != "next" {
		t.Fatalf("third Read = %q, %v; want %q, nil", rest[:n], err, "next")
	}
}

// An empty message must be skipped rather than surface as (0, nil), which io.ReadFull
// treats as a stalled reader.
func TestDatagramStreamSkipsEmptyMessages(t *testing.T) {
	t.Parallel()

	sub := &fakeSubstrate{inbox: [][]byte{{}, {}, []byte("payload")}}
	s := sub.stream()

	buf := make([]byte, 64)
	n, err := s.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got := string(buf[:n]); got != "payload" {
		t.Fatalf("Read = %q, want %q", got, "payload")
	}
	if sub.recvs != 3 {
		t.Fatalf("recv called %d times, want 3 (two empties skipped)", sub.recvs)
	}
}

func TestDatagramStreamRecvErrorIsSticky(t *testing.T) {
	t.Parallel()

	boom := errors.New("substrate gone")
	sub := &fakeSubstrate{recvErr: boom}
	s := sub.stream()

	for i := range 3 {
		if _, err := s.Read(make([]byte, 64)); !errors.Is(err, boom) {
			t.Fatalf("Read %d = %v, want %v", i, err, boom)
		}
	}
	if sub.recvs != 1 {
		t.Fatalf("recv called %d times after failing; a dead substrate must not be re-read", sub.recvs)
	}
}

func TestDatagramStreamWritesOneMessagePerCall(t *testing.T) {
	t.Parallel()

	sub := &fakeSubstrate{}
	s := sub.stream()

	for _, frame := range []string{"alpha", "beta", "gamma"} {
		n, err := s.Write([]byte(frame))
		if err != nil {
			t.Fatalf("Write %q: %v", frame, err)
		}
		if n != len(frame) {
			t.Fatalf("Write %q returned %d, want %d", frame, n, len(frame))
		}
	}
	// An empty write must not put an empty message on the wire for the far end to
	// skip; it is simply nothing to send.
	if n, err := s.Write(nil); n != 0 || err != nil {
		t.Fatalf("empty Write = %d, %v; want 0, nil", n, err)
	}

	if len(sub.sent) != 3 {
		t.Fatalf("substrate saw %d messages, want 3", len(sub.sent))
	}
	for i, want := range []string{"alpha", "beta", "gamma"} {
		if got := string(sub.sent[i]); got != want {
			t.Fatalf("message %d = %q, want %q", i, got, want)
		}
	}
}

func TestDatagramStreamWriteError(t *testing.T) {
	t.Parallel()

	boom := errors.New("datagram too large")
	sub := &fakeSubstrate{sendErr: boom}
	s := sub.stream()

	n, err := s.Write([]byte("payload"))
	if !errors.Is(err, boom) {
		t.Fatalf("Write = %v, want %v", err, boom)
	}
	if n != 0 {
		t.Fatalf("Write reported %d bytes written on failure, want 0", n)
	}
}

func TestDatagramStreamCloseIsIdempotent(t *testing.T) {
	t.Parallel()

	boom := errors.New("close failed")
	sub := &fakeSubstrate{closeErr: boom}
	s := sub.stream()

	for i := range 2 {
		if err := s.Close(); !errors.Is(err, boom) {
			t.Fatalf("Close %d = %v, want %v", i, err, boom)
		}
	}
	if err := s.Reset(); !errors.Is(err, boom) {
		t.Fatalf("Reset = %v, want %v", err, boom)
	}
	if sub.closals != 1 {
		t.Fatalf("substrate closed %d times, want 1", sub.closals)
	}
}
