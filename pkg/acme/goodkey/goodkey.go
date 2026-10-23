// Package goodkey refuses public keys a CA must not certify: RSA keys of an
// unapproved size or exponent, moduli with a small factor, moduli the
// Infineon ROCA flaw generated (CVE-2017-15361), moduli whose primes are
// close enough for Fermat's method to factor, and EC keys on an unapproved
// curve or off their curve. It is the issuance KeyValidator of the ACME
// server (pkg/acme/issuance.KeyValidator), the go-trusted-ca goodkey port.
//
// The rules follow the CA/Browser Forum Baseline Requirements §6.1.5 (key
// sizes), §6.1.6 (public key parameters: an odd RSA exponent of at least
// 65537 and no small factors, NIST SP 800-89 §5.3.3; EC point validation,
// NIST SP 800-56A Rev. 3 §5.6.2.3.3) and §6.1.1.3 (refusal of keys known to
// be weak: ROCA and Fermat-factorable moduli).
package goodkey

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"
	"slices"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

var (
	// ErrNilKey reports a nil public key.
	ErrNilKey = errors.New("goodkey: public key is nil")

	// ErrUnsupportedKeyType reports a key type the policy does not allow.
	ErrUnsupportedKeyType = errors.New("goodkey: unsupported key type")

	// ErrRSAKeySize reports an RSA modulus of an unapproved size.
	ErrRSAKeySize = errors.New("goodkey: RSA key size not allowed")

	// ErrRSAExponent reports an RSA public exponent that is even or below
	// 65537.
	ErrRSAExponent = errors.New("goodkey: RSA public exponent not allowed")

	// ErrRSASmallFactor reports an RSA modulus divisible by a prime below
	// 752.
	ErrRSASmallFactor = errors.New("goodkey: RSA modulus has a small prime factor")

	// ErrROCA reports an RSA modulus with the ROCA fingerprint.
	ErrROCA = errors.New("goodkey: RSA key is vulnerable to ROCA (CVE-2017-15361)")

	// ErrFermatFactorable reports an RSA modulus Fermat's method factors.
	ErrFermatFactorable = errors.New("goodkey: RSA modulus is factorable by Fermat's method")

	// ErrCurveNotAllowed reports an EC key on a curve the policy does not
	// allow.
	ErrCurveNotAllowed = errors.New("goodkey: elliptic curve not allowed")

	// ErrInvalidECPoint reports an EC public key that is not a valid point
	// of its curve.
	ErrInvalidECPoint = errors.New("goodkey: invalid elliptic curve point")
)

// DefaultFermatRounds is the number of Fermat factorisation steps tried
// above ceil(sqrt(N)). It finds every modulus whose primes differ by less
// than about 2^(bits/4) times the round count.
const DefaultFermatRounds = 110

// smallPrimeBound is the bound of the small-prime trial division: every
// prime below it is refused as a factor.
const smallPrimeBound = 752

// Policy names the keys a Validator accepts. The zero value accepts
// nothing; DefaultPolicy is the Baseline Requirements set.
type Policy struct {
	// RSAKeySizes are the allowed RSA modulus lengths in bits.
	RSAKeySizes []int

	// Curves are the allowed ECDSA curves.
	Curves []elliptic.Curve

	// AllowEd25519 accepts Ed25519 keys.
	AllowEd25519 bool

	// FermatRounds is the number of Fermat factorisation steps; zero uses
	// DefaultFermatRounds.
	FermatRounds int
}

// DefaultPolicy returns RSA 2048, 3072 and 4096, ECDSA P-256, P-384 and
// P-521 (Baseline Requirements §6.1.5) and Ed25519.
func DefaultPolicy() Policy {
	return Policy{
		RSAKeySizes:  []int{2048, 3072, 4096},
		Curves:       []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()},
		AllowEd25519: true,
		FermatRounds: DefaultFermatRounds,
	}
}

// Validator checks public keys against a Policy. It is safe for concurrent
// use.
type Validator struct {
	policy     Policy
	primorial  *big.Int
	rocaPrimes []rocaPrime
}

// New returns a Validator enforcing policy.
func New(policy Policy) *Validator {
	if policy.FermatRounds <= 0 {
		policy.FermatRounds = DefaultFermatRounds
	}
	return &Validator{
		policy:     policy,
		primorial:  primorial(smallPrimeBound),
		rocaPrimes: rocaFingerprints(),
	}
}

// CheckKey returns nil when key is acceptable and a wrapped sentinel error
// naming the first rule it breaks otherwise.
func (v *Validator) CheckKey(_ context.Context, key crypto.PublicKey) error {
	switch k := key.(type) {
	case nil:
		return ErrNilKey
	case *rsa.PublicKey:
		if k == nil {
			return ErrNilKey
		}
		return v.checkRSA(k)
	case *ecdsa.PublicKey:
		if k == nil {
			return ErrNilKey
		}
		return v.checkECDSA(k)
	case ed25519.PublicKey:
		if !v.policy.AllowEd25519 {
			return &errs.Detail{Err: ErrUnsupportedKeyType, Detail: "ed25519"}
		}
		if len(k) != ed25519.PublicKeySize {
			return &errs.Detail{Err: ErrInvalidECPoint, Detail: fmt.Sprintf("ed25519 key of %d bytes", len(k))}
		}
		return nil
	default:
		return &errs.Detail{Err: ErrUnsupportedKeyType, Detail: fmt.Sprintf("%T", key)}
	}
}

func (v *Validator) checkRSA(key *rsa.PublicKey) error {
	if key.N == nil || key.N.Sign() <= 0 {
		return &errs.Detail{Err: ErrRSAKeySize, Detail: "missing modulus"}
	}
	if bits := key.N.BitLen(); !slices.Contains(v.policy.RSAKeySizes, bits) {
		return &errs.Detail{Err: ErrRSAKeySize, Detail: fmt.Sprintf("%d bits", bits)}
	}
	if key.E < 65537 || key.E%2 == 0 {
		return &errs.Detail{Err: ErrRSAExponent, Detail: fmt.Sprintf("e=%d", key.E)}
	}
	if new(big.Int).GCD(nil, nil, key.N, v.primorial).Cmp(big.NewInt(1)) != 0 {
		return ErrRSASmallFactor
	}
	if v.hasROCAFingerprint(key.N) {
		return ErrROCA
	}
	if fermatFactorable(key.N, v.policy.FermatRounds) {
		return ErrFermatFactorable
	}
	return nil
}

func (v *Validator) checkECDSA(key *ecdsa.PublicKey) error {
	if key.Curve == nil || !slices.ContainsFunc(v.policy.Curves, func(c elliptic.Curve) bool {
		return c.Params().Name == key.Curve.Params().Name
	}) {
		return ErrCurveNotAllowed
	}
	// ECDH validates the point: on the curve and not the identity. The
	// allowed NIST curves have cofactor 1, so that is the full public key
	// validation of SP 800-56A Rev. 3 §5.6.2.3.3.
	if _, err := key.ECDH(); err != nil {
		return &errs.Detail{Err: ErrInvalidECPoint, Detail: err.Error()}
	}
	return nil
}

// fermatFactorable reports whether N = a^2 - b^2 for some a in
// [ceil(sqrt(N)), ceil(sqrt(N))+rounds), which happens when N's two primes
// are close.
func fermatFactorable(n *big.Int, rounds int) bool {
	a := new(big.Int).Sqrt(n)
	if new(big.Int).Mul(a, a).Cmp(n) < 0 {
		a.Add(a, big.NewInt(1))
	}
	b2 := new(big.Int)
	b := new(big.Int)
	one := big.NewInt(1)
	for range rounds {
		b2.Mul(a, a)
		b2.Sub(b2, n)
		b.Sqrt(b2)
		if new(big.Int).Mul(b, b).Cmp(b2) == 0 {
			return true
		}
		a.Add(a, one)
	}
	return false
}

// primorial returns the product of every prime below bound.
func primorial(bound int) *big.Int {
	product := big.NewInt(1)
	for _, p := range primesBelow(bound) {
		product.Mul(product, big.NewInt(int64(p)))
	}
	return product
}

// primesBelow returns the primes below bound by the sieve of Eratosthenes.
func primesBelow(bound int) []int {
	composite := make([]bool, bound)
	var primes []int
	for i := 2; i < bound; i++ {
		if composite[i] {
			continue
		}
		primes = append(primes, i)
		for j := i * i; j < bound; j += i {
			composite[j] = true
		}
	}
	return primes
}
