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

// Package decoy derives the public material of a factor's decoy enrollment:
// the stand-in go-qrdb's holder quorum challenges a name outside the roster
// with, so that an anonymous caller cannot tell a share holder from a
// stranger (go-qrdb authfactors.DecoyEnroller).
//
// Every value is derived with HKDF-SHA256 from the domain's decoy seed, the
// requested user id and a fixed purpose label, so the same (seed, userID)
// always yields the same enrollment, as a real holder's does. Keys are real
// keys of the requested type; a factor uses the private half at most to
// self-sign its decoy certificate and then drops it, so nothing answers a
// decoy challenge.
package decoy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"strconv"
	"time"

	"github.com/google/uuid"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

const (
	// MinSeedSize is the shortest decoy seed accepted. A shorter seed could
	// be guessed, and whoever guesses it can compute every decoy and so tell
	// decoys from holders. go-qrdb's seeds are 32 bytes.
	MinSeedSize = 16

	// rsaPublicExponent is the exponent of every derived RSA key, the one
	// every RSA key the factors enrol in practice uses.
	rsaPublicExponent = 65537

	// rsaMinBits and rsaMaxBits bound the derivable RSA sizes. Below 2048
	// no factor enrols; above 8192 a single derivation would take minutes.
	rsaMinBits = 2048
	rsaMaxBits = 8192

	// rsaPrimeAttemptsPerBit bounds the candidates tried for one prime. A
	// random odd candidate of b bits is prime with probability about
	// 2/(b ln 2), so 64*b candidates all failing has probability below
	// e^-88.
	rsaPrimeAttemptsPerBit = 64

	// scalarAttempts bounds the candidate scalars tried for one ECDSA key. A
	// candidate is rejected only when it is not below the curve order: for
	// P-256 and P-384 with probability under 2^-32, for P-521 (masked to 521
	// bits) under 1/2. 64 failures in a row do not happen.
	scalarAttempts = 64
)

// Key algorithms, as KeyShape names them.
const (
	AlgorithmECDSA   = "ecdsa"
	AlgorithmRSA     = "rsa"
	AlgorithmEd25519 = "ed25519"
)

// Epoch and epochSpan bound the validity start of a decoy certificate when
// no enrolled certificate gives one to imitate.
var (
	Epoch     = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	epochSpan = 365 * 24 * time.Hour
)

// KeyShape is the type and size of a public key: what a certificate or a
// challenge reveals about a key besides the key itself.
type KeyShape struct {
	// Algorithm is AlgorithmECDSA, AlgorithmRSA or AlgorithmEd25519.
	Algorithm string
	// Curve names the ECDSA curve, as its parameters do ("P-256").
	Curve string
	// Bits is the RSA modulus size.
	Bits int
}

// curves maps the name of each ECDSA curve Key can derive on to the curve.
var curves = map[string]elliptic.Curve{
	"P-256": elliptic.P256(),
	"P-384": elliptic.P384(),
	"P-521": elliptic.P521(),
}

// keyDerivers maps each key algorithm to the derivation of a key of a shape
// of that algorithm.
var keyDerivers = map[string]func(d *Deriver, purpose string, s KeyShape) (crypto.Signer, error){
	AlgorithmECDSA: func(d *Deriver, purpose string, s KeyShape) (crypto.Signer, error) {
		curve, ok := curves[s.Curve]
		if !ok {
			return nil, &DerivationError{Purpose: purpose}
		}
		key, err := d.ECDSAKey(purpose, curve)
		if err != nil {
			return nil, err
		}
		return key, nil
	},
	AlgorithmRSA: func(d *Deriver, purpose string, s KeyShape) (crypto.Signer, error) {
		key, err := d.RSAKey(purpose, s.Bits)
		if err != nil {
			return nil, err
		}
		return key, nil
	},
	AlgorithmEd25519: func(d *Deriver, purpose string, _ KeyShape) (crypto.Signer, error) {
		key, err := d.Ed25519Key(purpose)
		if err != nil {
			return nil, err
		}
		return key, nil
	},
}

// SeedError reports a decoy seed shorter than MinSeedSize.
type SeedError struct {
	// Size is the length supplied.
	Size int
}

// Error returns a human-readable description.
func (e *SeedError) Error() string {
	return "decoy: seed of " + strconv.Itoa(e.Size) + " bytes is shorter than " + strconv.Itoa(MinSeedSize)
}

// UserIDError reports an empty user id.
type UserIDError struct{}

// Error returns a human-readable description.
func (e *UserIDError) Error() string { return "decoy: user id must not be empty" }

// DerivationError reports that no value could be derived for a purpose.
type DerivationError struct {
	// Purpose names what was being derived.
	Purpose string
}

// Error returns a human-readable description.
func (e *DerivationError) Error() string { return "decoy: derivation failed for " + e.Purpose }

// RSASizeError reports an RSA modulus size that cannot be derived.
type RSASizeError struct {
	// Bits is the size requested.
	Bits int
}

// Error returns a human-readable description.
func (e *RSASizeError) Error() string {
	return "decoy: cannot derive a " + strconv.Itoa(e.Bits) + "-bit RSA key (want a multiple of 16 from 2048 to 8192)"
}

// Deriver derives one user's decoy material for one factor.
type Deriver struct {
	seed   []byte
	userID string
	prefix string
}

// New returns the Deriver for userID's decoy under the factor's label, which
// names the factor and the derivation version (e.g. "xkms/pkcs11-decoy/v1").
func New(label string, seed []byte, userID string) (*Deriver, error) {
	if len(seed) < MinSeedSize {
		return nil, &SeedError{Size: len(seed)}
	}
	if userID == "" {
		return nil, &UserIDError{}
	}
	return &Deriver{seed: seed, userID: userID, prefix: label + "\x00" + userID + "\x00"}, nil
}

// Enrollment assembles the decoy enrollment of factorName around its derived
// public key and metadata: a derived enrollment id, the requested user, and
// the tenant predominant in like. EnrolledAt stays zero, as nothing ever
// enrolled it.
func (d *Deriver) Enrollment(factorName string, like []*qrdbsdk.AuthFactorEnrollment, publicKey []byte, metadata map[string]string) (*qrdbsdk.AuthFactorEnrollment, error) {
	id, err := d.EnrollmentID()
	if err != nil {
		return nil, err
	}
	tenants := make([]string, 0, len(like))
	for _, e := range like {
		if e != nil {
			tenants = append(tenants, e.TenantID)
		}
	}
	return &qrdbsdk.AuthFactorEnrollment{
		EnrollmentID: id,
		UserID:       d.userID,
		FactorName:   factorName,
		TenantID:     Predominant(tenants, ""),
		PublicKey:    publicKey,
		Metadata:     metadata,
	}, nil
}

// MetadataValues returns the value of metadata key on each enrollment in
// like, "" where it is absent, for Predominant to choose from.
func MetadataValues(like []*qrdbsdk.AuthFactorEnrollment, key string) []string {
	values := make([]string, 0, len(like))
	for _, e := range like {
		if e != nil {
			values = append(values, e.Metadata[key])
		}
	}
	return values
}

// Bytes derives n bytes for purpose. Purposes are fixed labels without a NUL,
// so no (userID, purpose) pair shares its HKDF info with another.
func (d *Deriver) Bytes(purpose string, n int) ([]byte, error) {
	out, err := hkdf.Key(sha256.New, d.seed, nil, d.prefix+purpose, n)
	if err != nil {
		return nil, &DerivationError{Purpose: purpose}
	}
	return out, nil
}

// EnrollmentID derives a version-4 UUID, the form of the enrollment ids the
// factors assign to real enrollments.
func (d *Deriver) EnrollmentID() (string, error) {
	b, err := d.Bytes("enrollment-id", 16)
	if err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	id, err := uuid.FromBytes(b)
	if err != nil {
		return "", &DerivationError{Purpose: "enrollment-id"}
	}
	return id.String(), nil
}

// Time derives a time in [from, to] at one-second resolution, the resolution
// of a certificate's validity. A to before from yields from.
func (d *Deriver) Time(purpose string, from, to time.Time) (time.Time, error) {
	from = from.UTC().Truncate(time.Second)
	span := uint64(0)
	if s := to.UTC().Truncate(time.Second).Sub(from); s > 0 {
		span = uint64(s / time.Second)
	}
	b, err := d.Bytes(purpose, 8)
	if err != nil {
		return time.Time{}, err
	}
	offset := binary.BigEndian.Uint64(b) % (span + 1)
	return from.Add(time.Duration(offset) * time.Second), nil
}

// Serial derives a positive certificate serial number of size bytes, as a CA draws a random one:
// size uniform bytes with the sign bit cleared, so DER needs no leading zero.
func (d *Deriver) Serial(purpose string, size int) (*big.Int, error) {
	if size <= 0 {
		return nil, &DerivationError{Purpose: purpose}
	}
	b, err := d.Bytes(purpose, size)
	if err != nil {
		return nil, err
	}
	b[0] &= 0x7f
	serial := new(big.Int).SetBytes(b)
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	return serial, nil
}

// ECDSAKey derives an ECDSA key on curve.
func (d *Deriver) ECDSAKey(purpose string, curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	size := (curve.Params().BitSize + 7) / 8
	excess := uint(size*8 - curve.Params().BitSize)
	for attempt := 0; attempt < scalarAttempts; attempt++ {
		scalar, err := d.Bytes(purpose+"/"+strconv.Itoa(attempt), size)
		if err != nil {
			return nil, err
		}
		scalar[0] &= 0xff >> excess
		if key, err := ecdsa.ParseRawPrivateKey(curve, scalar); err == nil {
			return key, nil
		}
	}
	return nil, &DerivationError{Purpose: purpose}
}

// Ed25519Key derives an Ed25519 key.
func (d *Deriver) Ed25519Key(purpose string) (ed25519.PrivateKey, error) {
	seed, err := d.Bytes(purpose, ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// RSAKey derives an RSA key with a modulus of exactly bits bits and public
// exponent 65537. The primes are searched deterministically, which costs
// about as much as an ordinary RSA key generation of the same size.
func (d *Deriver) RSAKey(purpose string, bits int) (*rsa.PrivateKey, error) {
	if !RSASizeSupported(bits) {
		return nil, &RSASizeError{Bits: bits}
	}
	p, err := d.prime(purpose+"/p", bits/2)
	if err != nil {
		return nil, err
	}
	q, err := d.prime(purpose+"/q", bits/2)
	if err != nil {
		return nil, err
	}
	if p.Cmp(q) == 0 {
		return nil, &DerivationError{Purpose: purpose}
	}
	one := big.NewInt(1)
	phi := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: new(big.Int).Mul(p, q), E: rsaPublicExponent},
		D:         new(big.Int).ModInverse(big.NewInt(rsaPublicExponent), phi),
		Primes:    []*big.Int{p, q},
	}
	key.Precompute()
	if err := key.Validate(); err != nil {
		return nil, &DerivationError{Purpose: purpose}
	}
	return key, nil
}

// Key derives a key of shape s.
func (d *Deriver) Key(purpose string, s KeyShape) (crypto.Signer, error) {
	derive, ok := keyDerivers[s.Algorithm]
	if !ok {
		return nil, &DerivationError{Purpose: purpose}
	}
	return derive(d, purpose, s)
}

// ShapeOfKey classifies a public key. It reports false for a key Key cannot
// derive the like of.
func ShapeOfKey(pub crypto.PublicKey) (KeyShape, bool) {
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		name := key.Curve.Params().Name
		if _, ok := curves[name]; ok {
			return KeyShape{Algorithm: AlgorithmECDSA, Curve: name}, true
		}
	case *rsa.PublicKey:
		if bits := key.N.BitLen(); RSASizeSupported(bits) && key.E == rsaPublicExponent {
			return KeyShape{Algorithm: AlgorithmRSA, Bits: bits}, true
		}
	case ed25519.PublicKey:
		return KeyShape{Algorithm: AlgorithmEd25519}, true
	}
	return KeyShape{}, false
}

// Certificates returns the certificates like's enrollments hold as PEM
// public keys, skipping any enrollment that holds something else.
func Certificates(like []*qrdbsdk.AuthFactorEnrollment) []*x509.Certificate {
	certs := make([]*x509.Certificate, 0, len(like))
	for _, e := range like {
		if e == nil {
			continue
		}
		block, _ := pem.Decode(e.PublicKey)
		if block == nil || block.Type != "CERTIFICATE" {
			continue
		}
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			certs = append(certs, cert)
		}
	}
	return certs
}

// NotBeforeSpan returns the earliest and latest validity start among certs,
// within which a decoy certificate's start is derived, or the year from
// Epoch when certs is empty.
func NotBeforeSpan(certs []*x509.Certificate) (time.Time, time.Time) {
	if len(certs) == 0 {
		return Epoch, Epoch.Add(epochSpan)
	}
	from, to := certs[0].NotBefore, certs[0].NotBefore
	for _, cert := range certs[1:] {
		if cert.NotBefore.Before(from) {
			from = cert.NotBefore
		}
		if cert.NotBefore.After(to) {
			to = cert.NotBefore
		}
	}
	return from, to
}

// NonEmpty returns the non-empty values, for a choice in which an enrollment
// lacking a value must not make the decoy lack it too.
func NonEmpty(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// RSASizeSupported reports whether RSAKey can derive a key of bits bits. A
// factor treats an enrolled RSA key of any other size as a shape it cannot
// imitate.
func RSASizeSupported(bits int) bool {
	return bits >= rsaMinBits && bits <= rsaMaxBits && bits%16 == 0
}

// prime derives a prime of exactly bits bits whose predecessor is coprime to
// the public exponent. Its two top bits are set, so the product of two such
// primes has exactly twice as many bits.
func (d *Deriver) prime(purpose string, bits int) (*big.Int, error) {
	e := big.NewInt(rsaPublicExponent)
	one := big.NewInt(1)
	for attempt := 0; attempt < rsaPrimeAttemptsPerBit*bits; attempt++ {
		b, err := d.Bytes(purpose+"/"+strconv.Itoa(attempt), bits/8)
		if err != nil {
			return nil, err
		}
		b[0] |= 0xc0
		b[len(b)-1] |= 1
		p := new(big.Int).SetBytes(b)
		if !p.ProbablyPrime(20) {
			continue
		}
		if new(big.Int).GCD(nil, nil, e, new(big.Int).Sub(p, one)).Cmp(one) == 0 {
			return p, nil
		}
	}
	return nil, &DerivationError{Purpose: purpose}
}

// Signer wraps key so that every signature it makes is deterministic: ECDSA
// signs per RFC 6979, and Ed25519 and RSA PKCS#1 v1.5 are deterministic
// already. A decoy certificate is therefore the same on every derivation.
func Signer(key crypto.Signer) crypto.Signer {
	return deterministicSigner{key}
}

// deterministicSigner signs with no randomness.
type deterministicSigner struct {
	crypto.Signer
}

// Sign signs digest with the wrapped key, ignoring rand.
func (s deterministicSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.Signer.Sign(nil, digest, opts)
}

// Predominant returns the value occurring most often in values; on a tie, the
// one seen first. It returns fallback when values is empty.
func Predominant[T comparable](values []T, fallback T) T {
	counts := make(map[T]int, len(values))
	for _, v := range values {
		counts[v]++
	}
	best, bestCount := fallback, 0
	for _, v := range values {
		if counts[v] > bestCount {
			best, bestCount = v, counts[v]
		}
	}
	return best
}
