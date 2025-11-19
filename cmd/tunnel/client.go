package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
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
					"certificate fingerprint mismatch: expected %x, got %x",
					hex.EncodeToString(connToken.Fingerprint[:]),
					hex.EncodeToString(fingerprint[:]),
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

	for {
		localConn, err := listen.Accept()
		if err != nil {
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
