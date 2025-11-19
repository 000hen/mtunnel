package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"log"
	"time"

	"github.com/quic-go/quic-go"
)

func runHost(network string, forwardPort int) {
	cert, err := generateSelfSignedTLS()
	if err != nil {
		panic(err)
	}
	log.Println("Generated self-signed TLS certificate")
	fingerprint := getX509Fingerprint(cert.Leaf)
	log.Printf("Certificate Fingerprint: %s\n", hex.EncodeToString(fingerprint[:]))

	stunServer := "stun.l.google.com:19302"
	conn, publicAddr, err := openUDPForP2P(stunServer)
	if err != nil {
		log.Fatalf("Failed to query STUN server %s: %v", stunServer, err)
	}
	defer conn.Close()

	log.Printf("Public address obtained from STUN server %s: %s\n", stunServer, publicAddr)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"mtunnel"},
	}

	transport := &quic.Transport{
		Conn: conn,
	}

	listener, err := transport.Listen(tlsConfig, &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
	})
	if err != nil {
		log.Fatalf("Failed to start QUIC listener: %v", err)
	}
	log.Println("QUIC listener started, waiting for connections...")
	defer listener.Close()

	token := ConnectionToken{
		Fingerprint: fingerprint,
		Network:     network,
		Host:        publicAddr.IP,
		Port:        publicAddr.Port,
	}

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(token); err != nil {
		log.Fatalf("Failed to encode token: %v", err)
	}

	log.Println("Connection Token:")
	log.Println("-------------")
	log.Println(base64.StdEncoding.EncodeToString(buf.Bytes()))
	log.Println("-------------")

	for {
		ctx := context.Background()
		sess, err := listener.Accept(ctx)
		if err != nil {
			log.Fatalf("Failed to accept QUIC session: %v", err)
			continue
		}

		log.Println("New QUIC session accepted from", sess.RemoteAddr().String())

		// 持續接受該 session 中的多個 streams
		go func(session *quic.Conn) {
			for {
				ctx := context.Background()
				stream, err := session.AcceptStream(ctx)
				if err != nil {
					log.Println("Session closed or failed to accept stream:", err)
					return
				}

				go handleStreamToQUIC(stream, network, forwardPort)
			}
		}(sess)
	}
}
