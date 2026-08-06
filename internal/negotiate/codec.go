package negotiate

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	codecVersion = 1

	maxTierNameLen  = 32
	maxICEFieldLen  = 256
	maxCandidateLen = 4096
	maxCandidates   = 64
)

// ErrInvalidMessage reports a well-framed but malformed negotiation payload.
var ErrInvalidMessage = errors.New("invalid negotiate message")

func marshalHello(h Hello) ([]byte, error) {
	p := []byte{codecVersion, byte(len(h.SupportedTiers))}
	if len(h.SupportedTiers) > len(cascade) {
		return nil, invalidMessage("too many supported tiers: %d", len(h.SupportedTiers))
	}
	var err error
	for _, tier := range h.SupportedTiers {
		p, err = appendString(p, string(tier), maxTierNameLen)
		if err != nil {
			return nil, err
		}
	}
	p = append(p, h.WireGuardPubKey[:]...)
	p, err = appendString(p, string(h.RequiredTier), maxTierNameLen)
	if err != nil {
		return nil, err
	}
	if h.PunchProbe {
		p = append(p, 1)
	} else {
		p = append(p, 0)
	}
	return append(p, h.PunchAttempts), nil
}

func unmarshalHello(p []byte, h *Hello) error {
	d := decoder{p: p}
	if err := d.version(); err != nil {
		return err
	}
	count, err := d.byte()
	if err != nil {
		return err
	}
	if int(count) > len(cascade) {
		return invalidMessage("too many supported tiers: %d", count)
	}
	tiers := make([]Tier, int(count))
	for i := range tiers {
		value, err := d.string(maxTierNameLen)
		if err != nil {
			return err
		}
		tiers[i] = Tier(value)
	}
	key, err := d.bytes(len(h.WireGuardPubKey))
	if err != nil {
		return err
	}
	copy(h.WireGuardPubKey[:], key)
	required, err := d.string(maxTierNameLen)
	if err != nil {
		return err
	}
	probe, err := d.byte()
	if err != nil {
		return err
	}
	if probe > 1 {
		return invalidMessage("invalid punch probe")
	}
	attempts, err := d.byte()
	if err != nil {
		return err
	}
	if err := d.done(); err != nil {
		return err
	}
	h.SupportedTiers = tiers
	h.RequiredTier = Tier(required)
	h.PunchProbe = probe == 1
	h.PunchAttempts = attempts
	return nil
}

func marshalPunchInfo(p PunchInfo) ([]byte, error) {
	if len(p.ICECandidates) > maxCandidates {
		return nil, invalidMessage("too many ICE candidates: %d", len(p.ICECandidates))
	}
	if len(p.QUICCertFingerprint) != 0 && len(p.QUICCertFingerprint) != 32 {
		return nil, invalidMessage("invalid QUIC certificate fingerprint length: %d", len(p.QUICCertFingerprint))
	}
	out := []byte{codecVersion}
	var err error
	if out, err = appendString(out, p.ICEUfrag, maxICEFieldLen); err != nil {
		return nil, err
	}
	if out, err = appendString(out, p.ICEPwd, maxICEFieldLen); err != nil {
		return nil, err
	}
	out = append(out, byte(len(p.ICECandidates)))
	for _, candidate := range p.ICECandidates {
		if out, err = appendString(out, candidate, maxCandidateLen); err != nil {
			return nil, err
		}
	}
	out = append(out, byte(len(p.QUICCertFingerprint)))
	return append(out, p.QUICCertFingerprint...), nil
}

func unmarshalPunchInfo(data []byte, p *PunchInfo) error {
	d := decoder{p: data}
	if err := d.version(); err != nil {
		return err
	}
	ufrag, err := d.string(maxICEFieldLen)
	if err != nil {
		return err
	}
	pwd, err := d.string(maxICEFieldLen)
	if err != nil {
		return err
	}
	count, err := d.byte()
	if err != nil {
		return err
	}
	if int(count) > maxCandidates {
		return invalidMessage("too many ICE candidates: %d", count)
	}
	candidates := make([]string, int(count))
	for i := range candidates {
		if candidates[i], err = d.string(maxCandidateLen); err != nil {
			return err
		}
	}
	fingerprintLen, err := d.byte()
	if err != nil {
		return err
	}
	if fingerprintLen != 0 && fingerprintLen != 32 {
		return invalidMessage("invalid QUIC certificate fingerprint length: %d", fingerprintLen)
	}
	fingerprint, err := d.bytes(int(fingerprintLen))
	if err != nil {
		return err
	}
	if err := d.done(); err != nil {
		return err
	}
	p.ICEUfrag = ufrag
	p.ICEPwd = pwd
	p.ICECandidates = candidates
	p.QUICCertFingerprint = append(p.QUICCertFingerprint[:0], fingerprint...)
	return nil
}

func marshalAttempt(a Attempt) ([]byte, error) {
	p := []byte{codecVersion}
	var err error
	if p, err = appendString(p, string(a.Tier), maxTierNameLen); err != nil {
		return nil, err
	}
	if a.Commit {
		return append(p, 1), nil
	}
	return append(p, 0), nil
}

func unmarshalAttempt(data []byte, a *Attempt) error {
	d := decoder{p: data}
	if err := d.version(); err != nil {
		return err
	}
	tier, err := d.string(maxTierNameLen)
	if err != nil {
		return err
	}
	commit, err := d.byte()
	if err != nil {
		return err
	}
	if commit > 1 {
		return invalidMessage("invalid attempt commit")
	}
	if err := d.done(); err != nil {
		return err
	}
	a.Tier = Tier(tier)
	a.Commit = commit == 1
	return nil
}

func marshalPunchOutcome(p PunchOutcome) ([]byte, error) {
	if p.OK {
		return []byte{codecVersion, 1}, nil
	}
	return []byte{codecVersion, 0}, nil
}

func unmarshalPunchOutcome(data []byte, p *PunchOutcome) error {
	d := decoder{p: data}
	if err := d.version(); err != nil {
		return err
	}
	ok, err := d.byte()
	if err != nil {
		return err
	}
	if ok > 1 {
		return invalidMessage("invalid punch outcome")
	}
	if err := d.done(); err != nil {
		return err
	}
	p.OK = ok == 1
	return nil
}

func marshalMessage(msg any) ([]byte, error) {
	switch msg := msg.(type) {
	case Hello:
		return marshalHello(msg)
	case PunchInfo:
		return marshalPunchInfo(msg)
	case PunchOutcome:
		return marshalPunchOutcome(msg)
	case Attempt:
		return marshalAttempt(msg)
	default:
		return nil, fmt.Errorf("unsupported negotiate message type %T", msg)
	}
}

func unmarshalMessage(data []byte, msg any) error {
	switch msg := msg.(type) {
	case *Hello:
		return unmarshalHello(data, msg)
	case *PunchInfo:
		return unmarshalPunchInfo(data, msg)
	case *PunchOutcome:
		return unmarshalPunchOutcome(data, msg)
	case *Attempt:
		return unmarshalAttempt(data, msg)
	default:
		return fmt.Errorf("unsupported negotiate message type %T", msg)
	}
}

type decoder struct {
	p []byte
	o int
}

func (d *decoder) version() error {
	v, err := d.byte()
	if err != nil {
		return err
	}
	if v != codecVersion {
		return invalidMessage("unsupported codec version: %d", v)
	}
	return nil
}

func (d *decoder) byte() (byte, error) {
	if d.o == len(d.p) {
		return 0, invalidMessage("truncated payload")
	}
	v := d.p[d.o]
	d.o++
	return v, nil
}

func (d *decoder) bytes(n int) ([]byte, error) {
	if n < 0 || n > len(d.p)-d.o {
		return nil, invalidMessage("truncated payload")
	}
	v := d.p[d.o : d.o+n]
	d.o += n
	return v, nil
}

func (d *decoder) string(max int) (string, error) {
	var raw [2]byte
	b, err := d.bytes(len(raw))
	if err != nil {
		return "", err
	}
	copy(raw[:], b)
	n := int(binary.BigEndian.Uint16(raw[:]))
	if n > max {
		return "", invalidMessage("string length %d exceeds %d", n, max)
	}
	b, err = d.bytes(n)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (d *decoder) done() error {
	if d.o != len(d.p) {
		return invalidMessage("trailing payload bytes")
	}
	return nil
}

func appendString(dst []byte, value string, max int) ([]byte, error) {
	if len(value) > max {
		return nil, invalidMessage("string length %d exceeds %d", len(value), max)
	}
	var raw [2]byte
	binary.BigEndian.PutUint16(raw[:], uint16(len(value)))
	dst = append(dst, raw[:]...)
	return append(dst, value...), nil
}

func invalidMessage(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalidMessage}, args...)...)
}
