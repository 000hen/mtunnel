package main

import (
	"fmt"
	"io"
	"log"
	"net"

	"github.com/quic-go/quic-go"
)

func handleStreamToQUIC(stream *quic.Stream, network string, forwardPort int) {
	log.Printf("New stream %d accepted, forwarding to localhost:%d\n", stream.StreamID(), forwardPort)

	addr := fmt.Sprintf("localhost:%d", forwardPort)
	localConn, err := net.Dial(network, addr)
	if err != nil {
		log.Printf("Failed to connect to local service on %s: %v", addr, err)
		return
	}
	defer localConn.Close()

	log.Printf("Connected to local service on %s\n", addr)

	done := make(chan error, 2)

	go func() {
		_, err := io.Copy(stream, localConn)
		if err != nil && err != io.EOF {
			log.Printf("Error copying from local->QUIC: %v", err)
			done <- err
			return
		}

		if cerr := (*stream).Close(); cerr != nil {
			log.Printf("Error closing QUIC write side: %v", cerr)
		}

		if s, ok := localConn.(*net.TCPConn); ok {
			s.CloseWrite()
		}
		done <- nil
	}()

	go func() {
		_, err := io.Copy(localConn, stream)
		if err != nil && err != io.EOF {
			log.Printf("Error copying from QUIC->local: %v", err)
			done <- err
			return
		}

		if s, ok := localConn.(*net.TCPConn); ok {
			_ = s.CloseWrite()
		}
		done <- nil
	}()

	<-done
	<-done

	log.Printf("Data transfer completed for stream %d\n", stream.StreamID())
}

func handleQUICToStream(streamQUIC *quic.Stream, steamLocal net.Conn) {
	log.Printf("New stream %d accepted, forwarding to local connection\n", streamQUIC.StreamID())

	done := make(chan error, 2)

	go func() {
		_, err := io.Copy(steamLocal, streamQUIC)
		if err != nil && err != io.EOF {
			log.Printf("Error copying from QUIC->local: %v", err)
			done <- err
			return
		}

		if conn, ok := steamLocal.(*net.TCPConn); ok {
			conn.CloseWrite()
		}
		done <- nil
	}()

	go func() {
		_, err := io.Copy(streamQUIC, steamLocal)
		if err != nil && err != io.EOF {
			log.Printf("Error copying from local->QUIC: %v", err)
			done <- err
			return
		}

		if cerr := (*streamQUIC).Close(); cerr != nil {
			log.Printf("Error closing QUIC write side: %v", cerr)
		}

		if conn, ok := steamLocal.(*net.TCPConn); ok {
			_ = conn.CloseRead()
		}
		done <- nil
	}()

	<-done
	<-done

	log.Printf("Data transfer completed for stream %d\n", streamQUIC.StreamID())
}
