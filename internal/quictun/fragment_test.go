package quictun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

func TestDatagramCodecMessageSizeLimit(t *testing.T) {
	t.Parallel()

	message := bytes.Repeat([]byte("x"), maxDatagramMessage)
	fragments := encodedFragments(t, message)
	codec := newDatagramCodec(nil, nil)
	var got []byte
	for _, fragment := range fragments {
		if complete := codec.accept(fragment, time.Now()); complete != nil {
			got = complete
		}
	}
	if !bytes.Equal(got, message) {
		t.Fatalf("maximum message round trip = %d bytes, want %d", len(got), len(message))
	}

	tooLarge := newDatagramCodec(func([]byte) error { return nil }, nil)
	if err := tooLarge.Send(make([]byte, maxDatagramMessage+1)); !errors.Is(err, errDatagramTooLarge) {
		t.Fatalf("Send(max+1) = %v, want %v", err, errDatagramTooLarge)
	}
}

func TestDatagramCodecReassemblesReorderedDuplicates(t *testing.T) {
	t.Parallel()

	message := bytes.Repeat([]byte("fragmented message "), 150)
	fragments := encodedFragments(t, message)
	if len(fragments) < 2 {
		t.Fatal("test message was not fragmented")
	}

	codec := newDatagramCodec(nil, nil)
	var got [][]byte
	for _, fragment := range append(append([][]byte(nil), fragments[1:]...), fragments[0], fragments[1]) {
		if message := codec.accept(fragment, time.Now()); message != nil {
			got = append(got, message)
		}
	}
	if len(got) != 1 || !bytes.Equal(got[0], message) {
		t.Fatalf("reassembled messages = %d / %d bytes, want one %d-byte message", len(got), len(got[0]), len(message))
	}
}

func TestDatagramCodecDropsMalformedAndBoundsPartials(t *testing.T) {
	t.Parallel()

	codec := newDatagramCodec(nil, nil)
	now := time.Now()
	malformed := make([]byte, datagramHeaderSize)
	writeDatagramHeader(malformed, 1, 0, 1, maxDatagramMessage+1)
	if got := codec.accept(malformed, now); got != nil {
		t.Fatalf("malformed fragment produced %d bytes", len(got))
	}
	if len(codec.partial) != 0 || codec.reserved != 0 {
		t.Fatalf("malformed fragment allocated state: partial=%d reserved=%d", len(codec.partial), codec.reserved)
	}

	for id := range maxPartialMessages + 10 {
		fragment := make([]byte, datagramHeaderSize+datagramFragmentPayload)
		writeDatagramHeader(fragment, uint32(id+1), 0, 2, datagramFragmentPayload+1)
		codec.accept(fragment, now)
	}
	if len(codec.partial) > maxPartialMessages || codec.reserved > maxPartialBytes {
		t.Fatalf("partial state exceeded caps: partial=%d reserved=%d", len(codec.partial), codec.reserved)
	}

	codec.Close()
	if len(codec.partial) != 0 || codec.reserved != 0 {
		t.Fatalf("Close retained partial state: partial=%d reserved=%d", len(codec.partial), codec.reserved)
	}
}

func TestDatagramCodecExpiresPartialMessages(t *testing.T) {
	t.Parallel()

	message := bytes.Repeat([]byte("x"), datagramFragmentPayload+1)
	fragments := encodedFragments(t, message)
	codec := newDatagramCodec(nil, nil)
	now := time.Now()
	codec.accept(fragments[0], now)
	if len(codec.partial) != 1 {
		t.Fatalf("partial messages = %d, want 1", len(codec.partial))
	}

	other := encodedFragments(t, []byte("next"))[0]
	codec.accept(other, now.Add(partialTTL))
	if len(codec.partial) != 0 {
		t.Fatalf("expired partial message was retained: %d", len(codec.partial))
	}
}

func encodedFragments(t *testing.T, message []byte) [][]byte {
	t.Helper()
	var fragments [][]byte
	codec := newDatagramCodec(func(fragment []byte) error {
		fragments = append(fragments, append([]byte(nil), fragment...))
		return nil
	}, nil)
	if err := codec.Send(message); err != nil {
		t.Fatalf("encode %d-byte message: %v", len(message), err)
	}
	return fragments
}

func TestDatagramCodecRejectsInvalidCount(t *testing.T) {
	t.Parallel()

	fragment := make([]byte, datagramHeaderSize+1)
	writeDatagramHeader(fragment, 1, 0, 2, 1)
	codec := newDatagramCodec(nil, nil)
	if got := codec.accept(fragment, time.Now()); got != nil {
		t.Fatalf("invalid count produced %d bytes", len(got))
	}
	if len(codec.partial) != 0 {
		t.Fatalf("invalid count allocated %d partial messages", len(codec.partial))
	}

	// Keep this test coupled to the on-wire layout: a malformed total comes from
	// the peer, not from a Go int conversion.
	binary.BigEndian.PutUint32(fragment[12:16], uint32(maxDatagramMessage+1))
	if got := codec.accept(fragment, time.Now()); got != nil {
		t.Fatalf("oversized total produced %d bytes", len(got))
	}
}
