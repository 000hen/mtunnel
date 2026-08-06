package transport

import (
	"net"
	"testing"
	"time"
)

func TestConnStreamCloseWrite(t *testing.T) {
	t.Parallel()

	t.Run("delegates to underlying half-close", func(t *testing.T) {
		t.Parallel()

		conn := &closeWriteConn{}
		stream := ConnStream{Conn: conn}

		if err := stream.CloseWrite(); err != nil {
			t.Fatalf("CloseWrite() error = %v", err)
		}
		if conn.closeWriteCalls != 1 {
			t.Fatalf("CloseWrite() calls = %d, want 1", conn.closeWriteCalls)
		}
		if conn.closeCalls != 0 {
			t.Fatalf("Close() calls = %d, want 0", conn.closeCalls)
		}
	})

	t.Run("closes when half-close is unavailable", func(t *testing.T) {
		t.Parallel()

		conn := &testConn{}
		stream := ConnStream{Conn: conn}

		if err := stream.CloseWrite(); err != nil {
			t.Fatalf("CloseWrite() error = %v", err)
		}
		if conn.closeCalls != 1 {
			t.Fatalf("Close() calls = %d, want 1", conn.closeCalls)
		}
	})
}

type testConn struct {
	closeCalls int
}

func (c *testConn) Read([]byte) (int, error)         { return 0, nil }
func (c *testConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *testConn) Close() error                     { c.closeCalls++; return nil }
func (c *testConn) LocalAddr() net.Addr              { return testAddr("local") }
func (c *testConn) RemoteAddr() net.Addr             { return testAddr("remote") }
func (c *testConn) SetDeadline(time.Time) error      { return nil }
func (c *testConn) SetReadDeadline(time.Time) error  { return nil }
func (c *testConn) SetWriteDeadline(time.Time) error { return nil }

type closeWriteConn struct {
	testConn
	closeWriteCalls int
}

func (c *closeWriteConn) CloseWrite() error { c.closeWriteCalls++; return nil }

type testAddr string

func (a testAddr) Network() string { return string(a) }
func (a testAddr) String() string  { return string(a) }
