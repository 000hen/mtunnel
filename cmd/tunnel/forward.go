package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"syscall"

	"github.com/quic-go/quic-go"
)

func handleStreamToQUIC(stream *quic.Stream, network string, forwardPort int) {
	log.Printf("New stream %d accepted, forwarding to localhost:%d\n", stream.StreamID(), forwardPort)

	addr := fmt.Sprintf("localhost:%d", forwardPort)
	localConn, err := net.Dial(network, addr)
	if err != nil {
		log.Printf("Failed to connect to local service on %s: %v", addr, err)
		stream.CancelWrite(1)
		return
	}
	defer localConn.Close()

	log.Printf("Connected to local service on %s\n", addr)

	done := make(chan struct{})

	// Monitor for early stream closure
	go func() {
		<-stream.Context().Done()
		log.Printf("Stream %d context cancelled, initiating cleanup", stream.StreamID())
		localConn.Close()
	}()

	// local connection -> QUIC
	go func() {
		defer func() { done <- struct{}{} }()
		_, err := io.Copy(stream, localConn)
		if err != nil && !isClosedError(err) {
			log.Printf("Error copying from local->QUIC (stream %d): %v", stream.StreamID(), err)
			return
		}

		if cerr := stream.Close(); cerr != nil && !isClosedError(cerr) {
			log.Printf("Error closing QUIC write side (stream %d): %v", stream.StreamID(), cerr)
		}

		if s, ok := localConn.(*net.TCPConn); ok {
			s.CloseWrite()
		}
	}()

	// QUIC -> local connection
	go func() {
		defer func() { done <- struct{}{} }()
		_, err := io.Copy(localConn, stream)
		if err != nil && !isClosedError(err) {
			log.Printf("Error copying from QUIC->local (stream %d): %v", stream.StreamID(), err)
			return
		}

		if s, ok := localConn.(*net.TCPConn); ok {
			_ = s.CloseWrite()
		}
	}()

	<-done
	<-done

	log.Printf("Data transfer completed for stream %d\n", stream.StreamID())
}

func isClosedError(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, io.EOF) {
		return true
	}

	if errors.Is(err, net.ErrClosed) {
		return true
	}

	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.EPIPE, syscall.ECONNRESET:
			return true
		}
	}

	// Check for string patterns in error messages
	msg := err.Error()
	return strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "broken pipe")
}

func handleQUICToStream(streamQUIC *quic.Stream, steamLocal net.Conn) {
	log.Printf("New stream %d accepted, forwarding to local connection\n", streamQUIC.StreamID())

	defer steamLocal.Close()

	done := make(chan struct{})

	// Monitor for early stream closure
	go func() {
		<-streamQUIC.Context().Done()
		log.Printf("Stream %d context cancelled, initiating cleanup", streamQUIC.StreamID())
		steamLocal.Close()
	}()

	// QUIC -> local connection
	go func() {
		defer func() { done <- struct{}{} }()
		_, err := io.Copy(steamLocal, streamQUIC)
		if err != nil && !isClosedError(err) {
			log.Printf("Error copying from QUIC->local (stream %d): %v", streamQUIC.StreamID(), err)
			return
		}

		if conn, ok := steamLocal.(*net.TCPConn); ok {
			conn.CloseWrite()
		}
	}()

	// local connection -> QUIC
	go func() {
		defer func() { done <- struct{}{} }()
		_, err := io.Copy(streamQUIC, steamLocal)
		if err != nil && !isClosedError(err) {
			log.Printf("Error copying from local->QUIC (stream %d): %v", streamQUIC.StreamID(), err)
			return
		}

		if cerr := streamQUIC.Close(); cerr != nil && !isClosedError(cerr) {
			log.Printf("Error closing QUIC write side (stream %d): %v", streamQUIC.StreamID(), cerr)
		}

		if conn, ok := steamLocal.(*net.TCPConn); ok {
			_ = conn.CloseRead()
		}
	}()

	<-done
	<-done

	log.Printf("Data transfer completed for stream %d\n", streamQUIC.StreamID())
}
