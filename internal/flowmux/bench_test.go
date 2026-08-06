package flowmux

import (
	"context"
	"net"
	"testing"
)

// benchPayload is sized like a forwarded game packet, which is what the datagram
// sub-modes of both tiers actually carry - well inside the WireGuard device MTU and
// inside a QUIC DATAGRAM on a 1500-byte path.
const benchPayload = 1300

// sendOnlyMux builds a Mux whose Send discards and whose Recv parks until cleanup, so
// what a measurement sees is the framing and nothing else. Recv has to park rather than
// fail: an error there tears the Mux down and would end the run on its first iteration.
func sendOnlyMux(tb testing.TB) *Mux {
	tb.Helper()

	done := make(chan struct{})
	m := New(Config{
		Send: func([]byte) error { return nil },
		Recv: func() ([]byte, error) {
			<-done
			return nil, net.ErrClosed
		},
		Dialing: true,
	})
	tb.Cleanup(func() {
		close(done)
		_ = m.Close()
	})
	return m
}

// BenchmarkFlowSend measures the per-datagram cost of the send path with the channel
// underneath reduced to nothing.
//
// The review that prompted this (plan/review/009) argued the honest sequence was
// "benchmark, then decide". The number that matters is allocs/op: a frame built with
// make() costs one allocation and one size class per datagram, and the pooled form
// costs none in the steady state.
func BenchmarkFlowSend(b *testing.B) {
	m := sendOnlyMux(b)
	s, err := m.OpenStream(context.Background())
	if err != nil {
		b.Fatalf("OpenStream: %v", err)
	}

	payload := make([]byte, benchPayload)

	b.ReportAllocs()
	b.SetBytes(benchPayload)
	for b.Loop() {
		if _, err := s.Write(payload); err != nil {
			b.Fatalf("Write: %v", err)
		}
	}
}

// BenchmarkFlowSendParallel runs the same path from several goroutines at once. It is
// the case a per-flow scratch buffer could not serve without a mutex, and the reason
// send takes a buffer from the pool per call rather than holding one per flow.
func BenchmarkFlowSendParallel(b *testing.B) {
	m := sendOnlyMux(b)
	payload := make([]byte, benchPayload)

	b.ReportAllocs()
	b.SetBytes(benchPayload)
	b.RunParallel(func(pb *testing.PB) {
		s, err := m.OpenStream(context.Background())
		if err != nil {
			b.Errorf("OpenStream: %v", err)
			return
		}
		for pb.Next() {
			if _, err := s.Write(payload); err != nil {
				b.Errorf("Write: %v", err)
				return
			}
		}
	})
}

// TestFlowSendDoesNotAllocate is the assertion the benchmark exists to support. It is a
// test rather than a benchmark threshold so a regression fails the ordinary suite.
//
// One allocation is tolerated per datagram to leave room for the pool's own bookkeeping
// across Go versions. The pre-pool form allocated a whole frame per datagram, which is
// what this rules out.
// It deliberately does not call t.Parallel: testing.AllocsPerRun panics when a parallel
// test is in flight, because another test's allocations would be counted here.
func TestFlowSendDoesNotAllocate(t *testing.T) {
	m := sendOnlyMux(t)
	s, err := m.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}

	payload := make([]byte, benchPayload)
	// Warm the pool so the first Get is not counted as the steady state.
	if _, err := s.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got := testing.AllocsPerRun(200, func() {
		if _, err := s.Write(payload); err != nil {
			t.Fatalf("Write: %v", err)
		}
	})
	if got > 1 {
		t.Errorf("flow.send allocates %.1f objects per datagram, want at most 1", got)
	}
}
