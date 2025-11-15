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

// Package secretsharing implements Shamir's Secret Sharing Scheme.
//
// Shamir's Secret Sharing is a cryptographic algorithm that divides a secret
// into N shares, where any M shares (threshold) can reconstruct the original
// secret, but M-1 or fewer shares reveal absolutely no information about the
// secret. This is achieved through polynomial interpolation in a finite field.
//
// # Mathematical Foundation
//
// The scheme works by treating the secret as the constant term (a0) of a
// polynomial of degree M-1:
//
//	p(x) = a0 + a1*x + a2*x^2 + ... + a(M-1)*x^(M-1)
//
// Random coefficients a1 through a(M-1) are generated, and N shares are
// created by evaluating the polynomial at N distinct points. The secret
// can be recovered by interpolating the polynomial at x=0 using any M shares.
//
// All arithmetic is performed in the finite field GF(2^8) (also known as
// GF(256)), where addition is XOR and multiplication uses logarithm tables
// for efficiency.
//
// # Security Properties
//
// - Information-theoretic security: M-1 shares reveal no information
// - Perfect secrecy: The scheme is provably secure
// - Flexible threshold: Any M out of N shares can reconstruct
// - Integrity checking: SHA-256 checksums detect corruption
//
// # Usage Example
//
//	// Create a 3-of-5 scheme (need 3 shares to reconstruct)
//	shamir, err := secretsharing.NewShamir(&secretsharing.ShareConfig{
//	    Threshold:   3,
//	    TotalShares: 5,
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Split a secret into shares
//	secret := []byte("my secret data")
//	shares, err := shamir.Split(secret)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Distribute shares to different parties...
//
//	// Later, reconstruct with any 3 shares
//	reconstructed, err := shamir.Combine(shares[:3])
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// # Performance
//
// The implementation uses pre-computed logarithm and exponentiation tables
// for fast GF(256) arithmetic. Performance characteristics:
//
//   - Splitting: O(N * S) where N is shares and S is secret size
//   - Combining: O(M^2 * S) where M is threshold and S is secret size
//   - Memory: O(N * S) for shares storage
//
// Typical performance (on modern hardware):
//   - Small secrets (32 bytes): ~2μs split, ~1μs combine
//   - Medium secrets (1KB): ~50μs split, ~30μs combine
//   - Large secrets (1MB): ~48ms split, ~29ms combine
//
// # Constraints
//
//   - Threshold M must satisfy: 1 <= M <= N <= 255
//   - Secret size is limited only by available memory
//   - Share indices are bytes (1-255), index 0 is reserved
//
// # References
//
// - Shamir, Adi (1979). "How to Share a Secret"
// - Finite field arithmetic: GF(2^8) with AES polynomial (0x11B)
package secretsharing
