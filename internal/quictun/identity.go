package quictun

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// alpn identifies this tunnel's use of QUIC. Both sides must offer it or the
// handshake fails, which is a cheap guard against pointing the tier at something
// else that happens to speak QUIC on the same substrate.
const alpn = "mtunnel/1"

// certLifetime is generous because it is very nearly irrelevant: verification is
// pinned to a fingerprint rather than a chain, so expiry is never consulted. It
// exists so the certificate is well-formed for anything that does look.
const certLifetime = 365 * 24 * time.Hour

// Identity is one side's ephemeral QUIC credentials: a self-signed leaf generated
// fresh per process, plus the fingerprint the peer will pin it to.
//
// Nothing in this codebase persists an identity - not the libp2p peer ID, not the
// WireGuard static key - and this follows that precedent rather than introducing the
// first thing on disk.
type Identity struct {
	cert tls.Certificate

	// Fingerprint is the SHA-256 of the DER-encoded leaf. It travels to the peer in
	// negotiate.PunchInfo, over the Noise-encrypted libp2p stream, which is what makes
	// pinning meaningful: the value arrives already authenticated.
	Fingerprint [32]byte
}

// NewIdentity generates a fresh self-signed leaf certificate and its fingerprint.
func NewIdentity() (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("quictun: generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("quictun: generate serial: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "mtunnel"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(certLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return nil, fmt.Errorf("quictun: create certificate: %w", err)
	}

	return &Identity{
		cert:        tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv},
		Fingerprint: sha256.Sum256(der),
	}, nil
}

// clientTLS is the dialling side's config.
func (id *Identity) clientTLS(peer [32]byte) *tls.Config {
	return &tls.Config{
		Certificates:          []tls.Certificate{id.cert},
		NextProtos:            []string{alpn},
		MinVersion:            tls.VersionTLS13,
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: pinnedTo(peer),
	}
}

// serverTLS is the accepting side's config. RequireAnyClientCert is what makes the
// pin bidirectional: without it the client would present nothing and the host would
// have no certificate to check, leaving the tier authenticated in one direction only.
func (id *Identity) serverTLS(peer [32]byte) *tls.Config {
	return &tls.Config{
		Certificates:          []tls.Certificate{id.cert},
		NextProtos:            []string{alpn},
		MinVersion:            tls.VersionTLS13,
		ClientAuth:            tls.RequireAnyClientCert,
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: pinnedTo(peer),
	}
}

// pinnedTo builds the verification callback that replaces chain validation.
//
// InsecureSkipVerify reads alarming and would be, on its own: with no CA and no
// persisted identity there is nothing for a chain to prove, so accepting any
// certificate would accept an attacker's. What it actually does here is turn off the
// verification that cannot work and hand the decision to this callback, which
// requires the peer's leaf to hash to a value the peer already committed to over an
// authenticated channel. That is a stronger check than a public CA would give: it
// names exactly one acceptable certificate.
func pinnedTo(want [32]byte) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("quictun: peer presented no certificate")
		}
		got := sha256.Sum256(rawCerts[0])
		if subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
			return fmt.Errorf("quictun: peer certificate fingerprint %x does not match the pinned %x", got[:8], want[:8])
		}
		return nil
	}
}

// validFingerprint rejects an all-zero pin. Gob decodes a field the peer never sent
// as the zero value, so a peer that omitted its fingerprint would otherwise be
// checked against a value nothing can match - failing closed, but with an error that
// says "fingerprint mismatch" instead of "the peer sent no fingerprint".
func validFingerprint(fp [32]byte) bool {
	return fp != [32]byte{}
}
