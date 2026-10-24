// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package checkpoint

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// A Signer signs note text under one key name with a crypto.Signer. The
// private key never leaves the crypto.Signer, so any go-xkms key provider
// (software, PKCS#11, TPM 2.0, cloud KMS) can sign checkpoints.
type Signer struct {
	signer   crypto.Signer
	verifier *Verifier
	material []byte
}

// A SignerOption configures NewSigner.
type SignerOption func(*signerConfig)

type signerConfig struct {
	algorithm string
}

// WithAlgorithm names the algorithm the Signer uses instead of choosing it
// from the key. It is needed when more than one algorithm accepts the key,
// such as an RSA key, which every RSA algorithm accepts, or an ECDSA key
// bound to a digest other than SHA-256.
func WithAlgorithm(id string) SignerOption {
	return func(c *signerConfig) {
		c.algorithm = id
	}
}

// NewSigner returns a Signer for the key name and signer.
//
// The algorithm is chosen from signer's public key unless WithAlgorithm
// names one: the registered algorithm with an assigned signature type byte
// that accepts the key, else the one TypeExtended algorithm that accepts it.
// A key no algorithm accepts is refused with ErrUnsupportedKey, and a key
// several TypeExtended algorithms accept with ErrAmbiguousAlgorithm.
func NewSigner(name string, signer crypto.Signer, opts ...SignerOption) (*Signer, error) {
	if !validKeyName(name) {
		return nil, &errs.Detail{Err: ErrInvalidKeyName, Detail: strconv.Quote(name)}
	}
	if signer == nil {
		return nil, ErrNoSigner
	}
	var cfg signerConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	alg, material, err := selectAlgorithm(signer.Public(), cfg.algorithm)
	if err != nil {
		return nil, err
	}
	pub, err := alg.DecodePublicKey(material)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrInvalidAlgorithm, Detail: alg.ID + " cannot decode its own public key", Cause: err}
	}
	verifier := &Verifier{name: name, id: alg.computeKeyID(name, material), alg: alg, key: pub}
	return &Signer{signer: signer, verifier: verifier, material: material}, nil
}

// Name returns the key name.
func (s *Signer) Name() string {
	return s.verifier.name
}

// KeyID returns the key ID.
func (s *Signer) KeyID() uint32 {
	return s.verifier.id
}

// Algorithm returns the ID of the algorithm the Signer uses.
func (s *Signer) Algorithm() string {
	return s.verifier.alg.ID
}

// Verifier returns the Verifier for the Signer's public key.
func (s *Signer) Verifier() *Verifier {
	return s.verifier
}

// VerifierKey returns the signed-note §Verifier keys encoding of the
// Signer's public key: <name>+<hex(key ID)>+<base64(type || public key)>.
func (s *Signer) VerifierKey() string {
	keyBytes := append(s.verifier.alg.keyType(), s.material...)
	return fmt.Sprintf("%s+%08x+%s", s.verifier.name, s.verifier.id, base64.StdEncoding.EncodeToString(keyBytes))
}

// sign signs text and returns the signature bytes of a signature line:
// the big-endian key ID followed by the signature (signed-note §Format).
// The signature is verified before it is returned, so a crypto.Signer that
// signs with another scheme than the algorithm's is refused.
func (s *Signer) sign(text []byte) ([]byte, error) {
	alg := s.verifier.alg
	sig, err := s.signer.Sign(rand.Reader, digest(alg.SignerOpts.HashFunc(), text), alg.SignerOpts)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrSigningFailed, Detail: s.verifier.name, Cause: err}
	}
	if !alg.Verify(s.verifier.key, text, sig) {
		return nil, &errs.Detail{Err: ErrSigningFailed, Detail: s.verifier.name + ": signature does not verify under " + alg.ID}
	}
	out := binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(sig)), s.verifier.id)
	return append(out, sig...), nil
}

// A Verifier verifies note signatures under one key name, key ID and
// public key.
type Verifier struct {
	name string
	id   uint32
	alg  *Algorithm
	key  crypto.PublicKey
}

// NewVerifier parses a signed-note §Verifier keys encoding,
// <name>+<hex(key ID)>+<base64(type || public key)>, into a Verifier. The
// key ID must be eight lowercase hex digits, the base64 must be canonical,
// the signature type must be registered, and the key ID must be the one
// the algorithm derives from the name and public key.
func NewVerifier(vkey string) (*Verifier, error) {
	name, rest, ok := strings.Cut(vkey, "+")
	if !ok {
		return nil, &errs.Detail{Err: ErrMalformedVerifierKey, Detail: "missing key ID"}
	}
	if !validKeyName(name) {
		return nil, &errs.Detail{Err: ErrInvalidKeyName, Detail: strconv.Quote(name)}
	}
	idHex, b64, ok := strings.Cut(rest, "+")
	if !ok {
		return nil, &errs.Detail{Err: ErrMalformedVerifierKey, Detail: "missing public key"}
	}
	id, ok := parseKeyID(idHex)
	if !ok {
		return nil, &errs.Detail{Err: ErrMalformedVerifierKey, Detail: "key ID must be 8 lowercase hex digits"}
	}
	keyBytes, ok := decodeBase64(b64)
	if !ok {
		return nil, &errs.Detail{Err: ErrMalformedVerifierKey, Detail: "public key is not canonical base64"}
	}
	alg, material, err := lookupKeyType(keyBytes)
	if err != nil {
		return nil, err
	}
	pub, err := alg.DecodePublicKey(material)
	if err != nil {
		return nil, err
	}
	if alg.computeKeyID(name, material) != id {
		return nil, &errs.Detail{Err: ErrKeyIDMismatch, Detail: name + "+" + idHex}
	}
	return &Verifier{name: name, id: id, alg: alg, key: pub}, nil
}

// Name returns the key name.
func (v *Verifier) Name() string {
	return v.name
}

// KeyID returns the key ID.
func (v *Verifier) KeyID() uint32 {
	return v.id
}

// Algorithm returns the ID of the verifier's algorithm.
func (v *Verifier) Algorithm() string {
	return v.alg.ID
}

// Verify reports whether sig, without the key ID prefix, is a valid
// signature of text.
func (v *Verifier) Verify(text, sig []byte) bool {
	return v.alg.Verify(v.key, text, sig)
}

// validKeyName reports whether name can be a key name: non-empty UTF-8
// without Unicode spaces or plus signs (signed-note §Format), and without
// the control characters note text may not contain.
func validKeyName(name string) bool {
	if name == "" || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if r == '+' || unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// parseKeyID parses the eight lowercase hex digits of a verifier key's key
// ID (signed-note §Verifier keys).
func parseKeyID(s string) (uint32, bool) {
	if len(s) != 8 {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if (s[i] < '0' || s[i] > '9') && (s[i] < 'a' || s[i] > 'f') {
			return 0, false
		}
	}
	id, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return 0, false
	}
	return uint32(id), true
}

// decodeBase64 decodes canonical padded standard base64 (RFC 4648 §4),
// refusing non-zero padding bits and any encoding that does not round-trip.
func decodeBase64(s string) ([]byte, bool) {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(b) != s {
		return nil, false
	}
	return b, true
}
