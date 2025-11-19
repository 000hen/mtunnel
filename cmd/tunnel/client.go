package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
)

func runClient(token string, localPort int) {
	tokenBytes, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		log.Fatalf("Failed to decode token: %v", err)
	}

	var connToken ConnectionToken
	dec := gob.NewDecoder(bytes.NewReader(tokenBytes))
	if err := dec.Decode(&connToken); err != nil {
		log.Fatalf("Failed to decode connection token: %v", err)
	}
	log.Printf("Decoded token: %+v\n", connToken)

	tlsConfig := &tls.Config{
		NextProtos:         []string{"mtunnel"},
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("no client certificate provided")
			}

			clientCert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}

			fingerprint := getX509Fingerprint(clientCert)
			if fingerprint != connToken.Fingerprint {
				return fmt.Errorf(
					"certificate fingerprint mismatch: expected %X, got %X",
					connToken.Fingerprint,
					fingerprint,
				)
			}

			return nil
		},
	}

	ctx := context.Background()
	conn, err := quic.DialAddr(
		ctx,
		net.JoinHostPort(connToken.Host.String(), fmt.Sprintf("%d", connToken.Port)),
		tlsConfig,
		&quic.Config{
			MaxIdleTimeout:  30 * time.Second,
			KeepAlivePeriod: 10 * time.Second,
		},
	)
	if err != nil {
		log.Fatalf("Failed to connect to host: %v", err)
	}
	defer conn.CloseWithError(0, "client shutdown")
	log.Println("Connected to host at", conn.RemoteAddr().String())

	listen, err := net.Listen(connToken.Network, fmt.Sprintf("localhost:%d", localPort))
	if err != nil {
		log.Fatalf("Failed to listen on local port %d: %v", localPort, err)
	}
	defer listen.Close()
	log.Printf("Listening for local connections on %s\n", listen.Addr().String())

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-conn.Context().Done()
		cause := context.Cause(conn.Context())
		log.Printf("Connection lost: %v", cause)
		log.Println("Stopping local listener...")
		listen.Close()
	}()

	go func() {
		sig := <-sigChan
		log.Printf("Received signal: %v", sig)
		log.Println("Initiating graceful shutdown...")
		conn.CloseWithError(0, "client shutdown by user")
		listen.Close()
	}()

	for {
		localConn, err := listen.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				log.Println("Local listener closed, exiting...")
				return
			}

			log.Printf("Failed to accept local connection: %v", err)
			continue
		}

		stream, err := conn.OpenStreamSync(ctx)
		if err != nil {
			log.Printf("Failed to open stream: %v", err)
			localConn.Close()
			continue
		}

		go handleQUICToStream(stream, localConn)
	}
}
