package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"time"

	"github.com/pion/stun"
)

func generateSelfSignedTLS() (*tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mtunnel"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(nil, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	key := x509.MarshalPKCS1PrivateKey(priv)
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: key})

	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		return nil, err
	}

	return &cert, nil
}

func getX509Fingerprint(cert *x509.Certificate) [32]byte {
	hash := sha256.Sum256(cert.Raw)
	return hash
}

func openUDPForP2P(server string) (*net.UDPConn, *stun.XORMappedAddress, error) {
	stunAddr, err := net.ResolveUDPAddr("udp4", server)
	if err != nil {
		panic(err)
	}

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, nil, err
	}

	log.Println("Opened UDP socket on", conn.LocalAddr().String())

	message := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	if _, err := conn.WriteTo(message.Raw, stunAddr); err != nil {
		return nil, nil, err
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	buf := make([]byte, 1024)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil, nil, err
	}

	conn.SetReadDeadline(time.Time{})

	res := &stun.Message{Raw: buf[:n]}
	if err := res.Decode(); err != nil {
		return nil, nil, err
	}

	var xorAddr stun.XORMappedAddress
	if err := xorAddr.GetFrom(res); err != nil {
		return nil, nil, err
	}

	// go keepAlive(conn, stunAddr)

	return conn, &xorAddr, nil
}

func keepAlive(conn *net.UDPConn, target *net.UDPAddr) {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		log.Println("Sending keepalive to", target.String())
		_, _ = conn.WriteToUDP([]byte("keepalive"), target)
	}
}
