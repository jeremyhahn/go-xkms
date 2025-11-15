// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

// Package secretsharing implements cryptographic secret sharing schemes.
//
// This package provides Shamir's Secret Sharing Scheme, allowing a secret
// to be divided into N shares where any M shares can reconstruct the original
// secret, but M-1 shares reveal no information about the secret.
package secretsharing

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

// ShareConfig configures secret sharing parameters.
type ShareConfig struct {
	Threshold   int // M - minimum shares needed to reconstruct
	TotalShares int // N - total shares to create
}

// Share represents a single share of a secret.
type Share struct {
	Index    byte   // Share index (1-255)
	Value    []byte // Share value
	Checksum []byte // SHA-256 checksum for integrity
}

// Shamir implements Shamir's Secret Sharing Scheme using finite field
// arithmetic in GF(256).
type Shamir struct {
	config *ShareConfig
}

// NewShamir creates a new Shamir instance with the given configuration.
// Returns an error if the configuration is invalid.
func NewShamir(config *ShareConfig) (*Shamir, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}
	if config.Threshold < 1 {
		return nil, fmt.Errorf("threshold must be at least 1, got %d", config.Threshold)
	}
	if config.TotalShares < config.Threshold {
		return nil, fmt.Errorf("total shares (%d) must be >= threshold (%d)", config.TotalShares, config.Threshold)
	}
	if config.TotalShares > 255 {
		return nil, fmt.Errorf("total shares must be <= 255, got %d", config.TotalShares)
	}

	return &Shamir{
		config: config,
	}, nil
}

// Split divides a secret into N shares, requiring M to reconstruct.
// Uses finite field arithmetic (GF(256)) with secure random coefficients.
func (s *Shamir) Split(secret []byte) ([]Share, error) {
	if len(secret) == 0 {
		return nil, fmt.Errorf("secret cannot be empty")
	}

	shares := make([]Share, s.config.TotalShares)

	// Process each byte of the secret independently
	for i := 0; i < s.config.TotalShares; i++ {
		shares[i].Index = byte(i + 1) // Index starts at 1
		shares[i].Value = make([]byte, len(secret))
	}

	// For each byte in the secret, create a polynomial and evaluate it
	for byteIdx := 0; byteIdx < len(secret); byteIdx++ {
		// Generate random coefficients for polynomial of degree (threshold - 1)
		// p(x) = a0 + a1*x + a2*x^2 + ... + a(m-1)*x^(m-1)
		// where a0 is the secret byte
		coeffs := make([]byte, s.config.Threshold)
		coeffs[0] = secret[byteIdx]

		// Generate random coefficients for terms x^1 through x^(m-1)
		if s.config.Threshold > 1 {
			randomBytes := make([]byte, s.config.Threshold-1)
			if _, err := rand.Read(randomBytes); err != nil {
				return nil, fmt.Errorf("failed to generate random coefficients: %w", err)
			}
			copy(coeffs[1:], randomBytes)
		}

		// Evaluate polynomial at points 1, 2, ..., N
		for i := 0; i < s.config.TotalShares; i++ {
			x := byte(i + 1)
			shares[i].Value[byteIdx] = evaluatePolynomial(coeffs, x)
		}
	}

	// Calculate checksums for each share
	for i := range shares {
		shares[i].Checksum = calculateChecksum(shares[i].Index, shares[i].Value)
	}

	return shares, nil
}

// Combine reconstructs the secret from M or more shares.
// Uses Lagrange interpolation in GF(256).
func (s *Shamir) Combine(shares []Share) ([]byte, error) {
	if len(shares) < s.config.Threshold {
		return nil, fmt.Errorf("insufficient shares: need %d, got %d", s.config.Threshold, len(shares))
	}

	// Verify checksums
	if err := s.Verify(shares); err != nil {
		return nil, fmt.Errorf("share verification failed: %w", err)
	}

	// Use only the first threshold shares
	shares = shares[:s.config.Threshold]

	if len(shares[0].Value) == 0 {
		return nil, fmt.Errorf("shares have empty values")
	}

	secretLen := len(shares[0].Value)
	secret := make([]byte, secretLen)

	// Reconstruct each byte of the secret using Lagrange interpolation
	for byteIdx := 0; byteIdx < secretLen; byteIdx++ {
		// Evaluate polynomial at x=0 using Lagrange interpolation
		secret[byteIdx] = lagrangeInterpolate(shares, byteIdx)
	}

	return secret, nil
}

// Verify checks if shares have valid checksums.
func (s *Shamir) Verify(shares []Share) error {
	for i, share := range shares {
		if share.Index == 0 {
			return fmt.Errorf("share %d has invalid index 0", i)
		}
		if len(share.Value) == 0 {
			return fmt.Errorf("share %d has empty value", i)
		}
		if len(share.Checksum) == 0 {
			return fmt.Errorf("share %d has empty checksum", i)
		}

		expectedChecksum := calculateChecksum(share.Index, share.Value)
		if !bytesEqual(share.Checksum, expectedChecksum) {
			return fmt.Errorf("share %d has invalid checksum", i)
		}
	}
	return nil
}

// evaluatePolynomial evaluates a polynomial at point x in GF(256).
// Uses Horner's method: p(x) = a0 + x(a1 + x(a2 + ... + x*an))
func evaluatePolynomial(coeffs []byte, x byte) byte {
	if len(coeffs) == 0 {
		return 0
	}

	// Start with the highest degree coefficient
	result := coeffs[len(coeffs)-1]

	// Work backwards through coefficients
	for i := len(coeffs) - 2; i >= 0; i-- {
		result = gfAdd(gfMul(result, x), coeffs[i])
	}

	return result
}

// lagrangeInterpolate performs Lagrange interpolation at x=0 in GF(256)
// to reconstruct a single byte of the secret.
func lagrangeInterpolate(shares []Share, byteIdx int) byte {
	// Special case for 2 points - use direct formula
	// This avoids potential issues with Lagrange basis calculation
	if len(shares) == 2 {
		x1, y1 := shares[0].Index, shares[0].Value[byteIdx]
		x2, y2 := shares[1].Index, shares[1].Value[byteIdx]

		// From p(x) = a + b*x:
		// p(x1) = a XOR (b * x1) = y1
		// p(x2) = a XOR (b * x2) = y2
		// Therefore:
		// y1 XOR y2 = b * (x1 XOR x2)
		// b = (y1 XOR y2) / (x1 XOR x2)
		// a = y1 XOR (b * x1)

		b := gfMul(gfSub(y1, y2), gfInverse(gfSub(x1, x2)))
		a := gfSub(y1, gfMul(b, x1))
		return a
	}

	// General case: use Lagrange interpolation
	var result byte

	for i := range shares {
		xi := shares[i].Index
		yi := shares[i].Value[byteIdx]

		// Calculate Lagrange basis polynomial l_i(0)
		var numerator byte = 1
		var denominator byte = 1

		for j := range shares {
			if i == j {
				continue
			}
			xj := shares[j].Index

			// numerator *= (0 - xj) = xj (since subtraction is XOR and 0 XOR xj = xj)
			numerator = gfMul(numerator, xj)

			// denominator *= (xi - xj)
			denominator = gfMul(denominator, gfSub(xi, xj))
		}

		// Calculate basis value: numerator / denominator
		basis := gfMul(numerator, gfInverse(denominator))

		// Add yi * basis to result
		result = gfAdd(result, gfMul(yi, basis))
	}

	return result
}

// calculateChecksum computes SHA-256 checksum of share index and value.
func calculateChecksum(index byte, value []byte) []byte {
	h := sha256.New()
	h.Write([]byte{index})
	h.Write(value)
	return h.Sum(nil)
}

// bytesEqual performs constant-time comparison of two byte slices.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// GF(256) arithmetic operations using AES's finite field representation.
// The field is defined by the irreducible polynomial x^8 + x^4 + x^3 + x + 1.

// gfAdd performs addition in GF(256), which is XOR.
func gfAdd(a, b byte) byte {
	return a ^ b
}

// gfSub performs subtraction in GF(256), which is also XOR.
func gfSub(a, b byte) byte {
	return a ^ b
}

// gfMul performs multiplication in GF(256).
func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExpTable[(int(gfLogTable[a])+int(gfLogTable[b]))%255]
}

// gfInverse computes the multiplicative inverse in GF(256).
func gfInverse(a byte) byte {
	if a == 0 {
		panic("division by zero in GF(256)")
	}
	return gfExpTable[255-gfLogTable[a]]
}

// Pre-computed logarithm and exponentiation tables for GF(256).
// These tables enable efficient multiplication and division.
var (
	gfLogTable [256]byte
	gfExpTable [256]byte
)

func init() {
	// Initialize GF(256) logarithm and exponentiation tables
	// Using generator 0x03 and irreducible polynomial 0x11B (AES polynomial)
	var x byte = 1
	for i := 0; i < 255; i++ {
		gfExpTable[i] = x
		gfLogTable[x] = byte(i)

		// Multiply by generator (0x03)
		x = gfMultiply(x, 0x03)
	}
	gfExpTable[255] = gfExpTable[0]
}

// gfMultiply performs multiplication in GF(256) using the peasant algorithm.
// This is used only during table initialization.
func gfMultiply(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			p ^= a
		}
		highBit := a & 0x80
		a <<= 1
		if highBit != 0 {
			a ^= 0x1B // Irreducible polynomial x^8 + x^4 + x^3 + x + 1
		}
		b >>= 1
	}
	return p
}
