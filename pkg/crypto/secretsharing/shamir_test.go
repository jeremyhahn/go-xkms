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

package secretsharing

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestNewShamir tests Shamir instance creation with various configurations.
func TestNewShamir(t *testing.T) {
	tests := []struct {
		name      string
		config    *ShareConfig
		wantError bool
	}{
		{
			name: "valid configuration",
			config: &ShareConfig{
				Threshold:   3,
				TotalShares: 5,
			},
			wantError: false,
		},
		{
			name: "threshold equals total shares",
			config: &ShareConfig{
				Threshold:   5,
				TotalShares: 5,
			},
			wantError: false,
		},
		{
			name: "minimum valid configuration",
			config: &ShareConfig{
				Threshold:   1,
				TotalShares: 1,
			},
			wantError: false,
		},
		{
			name: "maximum valid configuration",
			config: &ShareConfig{
				Threshold:   255,
				TotalShares: 255,
			},
			wantError: false,
		},
		{
			name:      "nil config",
			config:    nil,
			wantError: true,
		},
		{
			name: "zero threshold",
			config: &ShareConfig{
				Threshold:   0,
				TotalShares: 5,
			},
			wantError: true,
		},
		{
			name: "threshold greater than total",
			config: &ShareConfig{
				Threshold:   6,
				TotalShares: 5,
			},
			wantError: true,
		},
		{
			name: "total shares exceeds limit",
			config: &ShareConfig{
				Threshold:   3,
				TotalShares: 256,
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shamir, err := NewShamir(tt.config)
			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if shamir == nil {
					t.Error("expected non-nil Shamir instance")
				}
			}
		})
	}
}

// TestSplit tests share generation.
func TestSplit(t *testing.T) {
	tests := []struct {
		name      string
		config    *ShareConfig
		secret    []byte
		wantError bool
	}{
		{
			name: "split small secret",
			config: &ShareConfig{
				Threshold:   3,
				TotalShares: 5,
			},
			secret:    []byte("hello world"),
			wantError: false,
		},
		{
			name: "split single byte",
			config: &ShareConfig{
				Threshold:   2,
				TotalShares: 3,
			},
			secret:    []byte{42},
			wantError: false,
		},
		{
			name: "split empty secret",
			config: &ShareConfig{
				Threshold:   3,
				TotalShares: 5,
			},
			secret:    []byte{},
			wantError: true,
		},
		{
			name: "threshold of 1",
			config: &ShareConfig{
				Threshold:   1,
				TotalShares: 5,
			},
			secret:    []byte("test"),
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shamir, err := NewShamir(tt.config)
			if err != nil {
				t.Fatalf("failed to create Shamir: %v", err)
			}

			shares, err := shamir.Split(tt.secret)
			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			// Verify we got the correct number of shares
			if len(shares) != tt.config.TotalShares {
				t.Errorf("expected %d shares, got %d", tt.config.TotalShares, len(shares))
			}

			// Verify each share has correct properties
			for i, share := range shares {
				if share.Index != byte(i+1) {
					t.Errorf("share %d has wrong index: expected %d, got %d", i, i+1, share.Index)
				}
				if len(share.Value) != len(tt.secret) {
					t.Errorf("share %d has wrong value length: expected %d, got %d", i, len(tt.secret), len(share.Value))
				}
				if len(share.Checksum) == 0 {
					t.Errorf("share %d has empty checksum", i)
				}
			}

			// Verify checksums are valid
			if err := shamir.Verify(shares); err != nil {
				t.Errorf("share verification failed: %v", err)
			}
		})
	}
}

// TestCombine tests secret reconstruction with M shares.
func TestCombine(t *testing.T) {
	tests := []struct {
		name   string
		config *ShareConfig
		secret []byte
	}{
		{
			name: "combine with exact threshold",
			config: &ShareConfig{
				Threshold:   3,
				TotalShares: 5,
			},
			secret: []byte("hello world"),
		},
		{
			name: "combine with all shares",
			config: &ShareConfig{
				Threshold:   3,
				TotalShares: 5,
			},
			secret: []byte("test secret"),
		},
		{
			name: "combine single byte",
			config: &ShareConfig{
				Threshold:   2,
				TotalShares: 4,
			},
			secret: []byte{123},
		},
		{
			name: "threshold of 1",
			config: &ShareConfig{
				Threshold:   1,
				TotalShares: 3,
			},
			secret: []byte("any share works"),
		},
		{
			name: "binary data",
			config: &ShareConfig{
				Threshold:   3,
				TotalShares: 5,
			},
			secret: []byte{0x00, 0xFF, 0x80, 0x7F, 0x01, 0xFE},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shamir, err := NewShamir(tt.config)
			if err != nil {
				t.Fatalf("failed to create Shamir: %v", err)
			}

			shares, err := shamir.Split(tt.secret)
			if err != nil {
				t.Fatalf("failed to split secret: %v", err)
			}

			// Test reconstruction with exact threshold
			reconstructed, err := shamir.Combine(shares[:tt.config.Threshold])
			if err != nil {
				t.Errorf("failed to combine shares: %v", err)
				return
			}

			if !bytes.Equal(reconstructed, tt.secret) {
				t.Errorf("reconstructed secret doesn't match original:\ngot:  %v\nwant: %v", reconstructed, tt.secret)
			}

			// Test reconstruction with all shares
			reconstructedAll, err := shamir.Combine(shares)
			if err != nil {
				t.Errorf("failed to combine all shares: %v", err)
				return
			}

			if !bytes.Equal(reconstructedAll, tt.secret) {
				t.Errorf("reconstructed secret (all shares) doesn't match original:\ngot:  %v\nwant: %v", reconstructedAll, tt.secret)
			}

			// Test with different combinations of threshold shares
			if tt.config.TotalShares > tt.config.Threshold {
				// Try last M shares
				reconstructedLast, err := shamir.Combine(shares[tt.config.TotalShares-tt.config.Threshold:])
				if err != nil {
					t.Errorf("failed to combine last M shares: %v", err)
					return
				}
				if !bytes.Equal(reconstructedLast, tt.secret) {
					t.Errorf("reconstructed secret (last M shares) doesn't match original")
				}

				// Try middle M shares if possible
				if tt.config.TotalShares >= tt.config.Threshold+2 {
					reconstructedMiddle, err := shamir.Combine(shares[1 : tt.config.Threshold+1])
					if err != nil {
						t.Errorf("failed to combine middle M shares: %v", err)
						return
					}
					if !bytes.Equal(reconstructedMiddle, tt.secret) {
						t.Errorf("reconstructed secret (middle M shares) doesn't match original")
					}
				}
			}
		})
	}
}

// TestCombineInsufficient tests failure with M-1 shares.
func TestCombineInsufficient(t *testing.T) {
	shamir, err := NewShamir(&ShareConfig{
		Threshold:   3,
		TotalShares: 5,
	})
	if err != nil {
		t.Fatalf("failed to create Shamir: %v", err)
	}

	secret := []byte("secret data")
	shares, err := shamir.Split(secret)
	if err != nil {
		t.Fatalf("failed to split secret: %v", err)
	}

	// Try with M-1 shares
	_, err = shamir.Combine(shares[:2])
	if err == nil {
		t.Error("expected error when combining with insufficient shares, got nil")
	}

	// Try with 0 shares
	_, err = shamir.Combine([]Share{})
	if err == nil {
		t.Error("expected error when combining with no shares, got nil")
	}
}

// TestCombineWrongShares tests failure with corrupted shares.
func TestCombineWrongShares(t *testing.T) {
	shamir, err := NewShamir(&ShareConfig{
		Threshold:   3,
		TotalShares: 5,
	})
	if err != nil {
		t.Fatalf("failed to create Shamir: %v", err)
	}

	secret := []byte("secret data")
	shares, err := shamir.Split(secret)
	if err != nil {
		t.Fatalf("failed to split secret: %v", err)
	}

	t.Run("corrupted value", func(t *testing.T) {
		corruptedShares := make([]Share, len(shares))
		copy(corruptedShares, shares)
		// Corrupt a share value
		corruptedShares[0].Value[0] ^= 0xFF

		_, err := shamir.Combine(corruptedShares[:3])
		if err == nil {
			t.Error("expected error when combining with corrupted share, got nil")
		}
	})

	t.Run("corrupted checksum", func(t *testing.T) {
		corruptedShares := make([]Share, len(shares))
		copy(corruptedShares, shares)
		// Corrupt a share checksum
		corruptedShares[0].Checksum[0] ^= 0xFF

		_, err := shamir.Combine(corruptedShares[:3])
		if err == nil {
			t.Error("expected error when combining with corrupted checksum, got nil")
		}
	})

	t.Run("zero index", func(t *testing.T) {
		corruptedShares := make([]Share, len(shares))
		copy(corruptedShares, shares)
		corruptedShares[0].Index = 0

		_, err := shamir.Combine(corruptedShares[:3])
		if err == nil {
			t.Error("expected error when combining with zero index, got nil")
		}
	})
}

// TestVerify tests share verification.
func TestVerify(t *testing.T) {
	shamir, err := NewShamir(&ShareConfig{
		Threshold:   3,
		TotalShares: 5,
	})
	if err != nil {
		t.Fatalf("failed to create Shamir: %v", err)
	}

	secret := []byte("test secret")
	shares, err := shamir.Split(secret)
	if err != nil {
		t.Fatalf("failed to split secret: %v", err)
	}

	t.Run("valid shares", func(t *testing.T) {
		if err := shamir.Verify(shares); err != nil {
			t.Errorf("verification failed for valid shares: %v", err)
		}
	})

	t.Run("corrupted value", func(t *testing.T) {
		corruptedShares := make([]Share, len(shares))
		copy(corruptedShares, shares)
		corruptedShares[0].Value[0] ^= 0xFF

		if err := shamir.Verify(corruptedShares); err == nil {
			t.Error("expected verification to fail for corrupted value")
		}
	})

	t.Run("empty value", func(t *testing.T) {
		invalidShares := []Share{
			{Index: 1, Value: []byte{}, Checksum: []byte{1, 2, 3}},
		}
		if err := shamir.Verify(invalidShares); err == nil {
			t.Error("expected verification to fail for empty value")
		}
	})

	t.Run("empty checksum", func(t *testing.T) {
		invalidShares := []Share{
			{Index: 1, Value: []byte{1, 2, 3}, Checksum: []byte{}},
		}
		if err := shamir.Verify(invalidShares); err == nil {
			t.Error("expected verification to fail for empty checksum")
		}
	})

	t.Run("zero index", func(t *testing.T) {
		invalidShares := []Share{
			{Index: 0, Value: []byte{1, 2, 3}, Checksum: []byte{1, 2, 3}},
		}
		if err := shamir.Verify(invalidShares); err == nil {
			t.Error("expected verification to fail for zero index")
		}
	})
}

// TestLargeSecret tests with a 1MB secret.
func TestLargeSecret(t *testing.T) {
	shamir, err := NewShamir(&ShareConfig{
		Threshold:   3,
		TotalShares: 5,
	})
	if err != nil {
		t.Fatalf("failed to create Shamir: %v", err)
	}

	// Generate 1MB random secret
	secret := make([]byte, 1024*1024)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("failed to generate random secret: %v", err)
	}

	shares, err := shamir.Split(secret)
	if err != nil {
		t.Fatalf("failed to split large secret: %v", err)
	}

	// Verify shares
	if len(shares) != 5 {
		t.Errorf("expected 5 shares, got %d", len(shares))
	}

	for i, share := range shares {
		if len(share.Value) != len(secret) {
			t.Errorf("share %d has wrong value length: expected %d, got %d", i, len(secret), len(share.Value))
		}
	}

	// Reconstruct with threshold shares
	reconstructed, err := shamir.Combine(shares[:3])
	if err != nil {
		t.Fatalf("failed to combine shares: %v", err)
	}

	if !bytes.Equal(reconstructed, secret) {
		t.Error("reconstructed large secret doesn't match original")
	}
}

// TestSecurityProperty tests that M-1 shares reveal no information.
func TestSecurityProperty(t *testing.T) {
	shamir, err := NewShamir(&ShareConfig{
		Threshold:   3,
		TotalShares: 5,
	})
	if err != nil {
		t.Fatalf("failed to create Shamir: %v", err)
	}

	// Create two different secrets
	secret1 := []byte("secret one")
	secret2 := []byte("secret two")

	shares1, err := shamir.Split(secret1)
	if err != nil {
		t.Fatalf("failed to split secret1: %v", err)
	}

	shares2, err := shamir.Split(secret2)
	if err != nil {
		t.Fatalf("failed to split secret2: %v", err)
	}

	// With M-1 shares, we should not be able to distinguish which secret they came from
	// This is a basic sanity check - full cryptographic proof requires information theory
	if bytes.Equal(shares1[0].Value, secret1) {
		t.Error("single share should not reveal the secret")
	}
	if bytes.Equal(shares2[0].Value, secret2) {
		t.Error("single share should not reveal the secret")
	}
}

// TestDifferentShareCombinations tests various combinations of shares.
func TestDifferentShareCombinations(t *testing.T) {
	shamir, err := NewShamir(&ShareConfig{
		Threshold:   3,
		TotalShares: 7,
	})
	if err != nil {
		t.Fatalf("failed to create Shamir: %v", err)
	}

	secret := []byte("test secret for combinations")
	shares, err := shamir.Split(secret)
	if err != nil {
		t.Fatalf("failed to split secret: %v", err)
	}

	// Test various combinations of 3 shares from 7
	combinations := [][]int{
		{0, 1, 2},
		{0, 3, 6},
		{1, 4, 5},
		{2, 3, 4},
		{4, 5, 6},
		{0, 2, 4},
	}

	for _, combo := range combinations {
		selectedShares := []Share{shares[combo[0]], shares[combo[1]], shares[combo[2]]}

		reconstructed, err := shamir.Combine(selectedShares)
		if err != nil {
			t.Errorf("failed to combine shares %v: %v", combo, err)
			continue
		}

		if !bytes.Equal(reconstructed, secret) {
			t.Errorf("combination %v failed to reconstruct secret correctly", combo)
		}
	}
}

// TestGFArithmetic tests the GF(256) arithmetic operations.
func TestGFArithmetic(t *testing.T) {
	t.Run("addition is XOR", func(t *testing.T) {
		if gfAdd(5, 3) != (5 ^ 3) {
			t.Error("GF addition should be XOR")
		}
	})

	t.Run("subtraction is XOR", func(t *testing.T) {
		if gfSub(5, 3) != (5 ^ 3) {
			t.Error("GF subtraction should be XOR")
		}
	})

	t.Run("multiplication by zero", func(t *testing.T) {
		if gfMul(5, 0) != 0 {
			t.Error("multiplication by zero should be zero")
		}
		if gfMul(0, 5) != 0 {
			t.Error("multiplication by zero should be zero")
		}
	})

	t.Run("multiplication identity", func(t *testing.T) {
		if gfMul(5, 1) != 5 {
			t.Error("multiplication by one should be identity")
		}
	})

	t.Run("multiplication is commutative", func(t *testing.T) {
		a, b := byte(5), byte(7)
		if gfMul(a, b) != gfMul(b, a) {
			t.Error("multiplication should be commutative")
		}
	})

	t.Run("inverse property", func(t *testing.T) {
		for a := byte(1); a != 0; a++ { // Loop through all non-zero elements
			inv := gfInverse(a)
			if gfMul(a, inv) != 1 {
				t.Errorf("inverse of %d failed: %d * %d = %d", a, a, inv, gfMul(a, inv))
			}
		}
	})
}

// TestPolynomialEvaluation tests polynomial evaluation.
func TestPolynomialEvaluation(t *testing.T) {
	t.Run("constant polynomial", func(t *testing.T) {
		coeffs := []byte{42}
		// p(x) = 42 for any x
		for x := byte(1); x <= 10; x++ {
			result := evaluatePolynomial(coeffs, x)
			if result != 42 {
				t.Errorf("p(%d) = %d, want 42", x, result)
			}
		}
	})

	t.Run("empty polynomial", func(t *testing.T) {
		coeffs := []byte{}
		result := evaluatePolynomial(coeffs, 5)
		if result != 0 {
			t.Errorf("empty polynomial should evaluate to 0, got %d", result)
		}
	})

	t.Run("linear polynomial", func(t *testing.T) {
		// p(x) = 1 + 2x in GF(256)
		coeffs := []byte{1, 2}
		// p(0) = 1
		// p(1) = 1 + 2*1 = gfAdd(1, gfMul(2,1))
		p1 := evaluatePolynomial(coeffs, 1)
		expected := gfAdd(1, gfMul(2, 1))
		if p1 != expected {
			t.Errorf("p(1) = %d, want %d", p1, expected)
		}
	})
}

// BenchmarkSplit benchmarks share generation.
func BenchmarkSplit(b *testing.B) {
	benchmarks := []struct {
		name       string
		secretSize int
		threshold  int
		totalShare int
	}{
		{"Small-3of5", 32, 3, 5},
		{"Medium-3of5", 1024, 3, 5},
		{"Large-3of5", 1024 * 1024, 3, 5},
		{"Small-5of10", 32, 5, 10},
		{"Medium-5of10", 1024, 5, 10},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			shamir, err := NewShamir(&ShareConfig{
				Threshold:   bm.threshold,
				TotalShares: bm.totalShare,
			})
			if err != nil {
				b.Fatalf("failed to create Shamir: %v", err)
			}

			secret := make([]byte, bm.secretSize)
			_, _ = rand.Read(secret)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := shamir.Split(secret)
				if err != nil {
					b.Fatalf("split failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkCombine benchmarks secret reconstruction.
func BenchmarkCombine(b *testing.B) {
	benchmarks := []struct {
		name       string
		secretSize int
		threshold  int
		totalShare int
	}{
		{"Small-3of5", 32, 3, 5},
		{"Medium-3of5", 1024, 3, 5},
		{"Large-3of5", 1024 * 1024, 3, 5},
		{"Small-5of10", 32, 5, 10},
		{"Medium-5of10", 1024, 5, 10},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			shamir, err := NewShamir(&ShareConfig{
				Threshold:   bm.threshold,
				TotalShares: bm.totalShare,
			})
			if err != nil {
				b.Fatalf("failed to create Shamir: %v", err)
			}

			secret := make([]byte, bm.secretSize)
			_, _ = rand.Read(secret)

			shares, err := shamir.Split(secret)
			if err != nil {
				b.Fatalf("split failed: %v", err)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := shamir.Combine(shares[:bm.threshold])
				if err != nil {
					b.Fatalf("combine failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkGFOperations benchmarks GF(256) operations.
func BenchmarkGFOperations(b *testing.B) {
	b.Run("Add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = gfAdd(byte(i), byte(i+1))
		}
	})

	b.Run("Mul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = gfMul(byte(i%255+1), byte((i+1)%255+1))
		}
	})

	b.Run("Inverse", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = gfInverse(byte(i%255 + 1))
		}
	})
}

// TestGFInverse_ZeroPanics tests that gfInverse panics when called with zero.
func TestGFInverse_ZeroPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("gfInverse(0) should panic but did not")
		}
	}()
	_ = gfInverse(0)
}
