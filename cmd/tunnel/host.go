package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"log"
	"os"
	"os/signal"
	"syscall"
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

	encodedToken := base64.StdEncoding.EncodeToString(buf.Bytes())

	log.Println("Connection Token:")
	log.Println("-------------")
	log.Println(encodedToken)
	log.Println("-------------")

	sendOutputAction(OutputAction{
		Action: TOKEN,
		Token:  encodedToken,
	})

	sessions := NewSessionManager()
	go handleIOAction(sessions)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Printf("Received signal: %v", sig)
		log.Println("Initiating graceful shutdown...")
		sessions.CloseAllSessions()
		listener.Close()
	}()

	for {
		ctx := context.Background()
		sess, err := listener.Accept(ctx)
		if err != nil {
			if err == quic.ErrServerClosed {
				log.Println("QUIC listener closed, exiting...")
				return
			}

			log.Fatalf("Failed to accept QUIC session: %v", err)
			continue
		}

		log.Println("New QUIC session accepted from", sess.RemoteAddr().String())
		session := sessions.AddSession(sess)

		go session.HandleSession(sessions, network, forwardPort, handleStreamToQUIC)
	}
}
