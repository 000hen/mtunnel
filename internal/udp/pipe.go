package udp

import (
	"net"
	"sync"

	"mtunnel-libp2p/internal/transport"
)

// pipeDatagrams forwards datagrams in both directions between a tunnel stream and
// a connected UDP socket on the host side. Unlike the TCP pipe (which streams raw
// bytes), each direction preserves datagram boundaries via the length-prefix
// framing. It returns once either side fails; closing one endpoint unblocks the
// other (a connected UDP socket never reaches EOF on its own).
func pipeDatagrams(s transport.Stream, conn net.Conn) {
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
