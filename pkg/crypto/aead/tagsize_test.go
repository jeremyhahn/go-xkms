// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package aead

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"testing"
)

func testBlock(t *testing.T) cipher.Block {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i * 7)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	return block
}

// TestNewGCM_ProducesTheLeadingBitsOfTheFullTag checks the truncation is the
// one NIST SP 800-38D section 5.2.1.2 defines -- the leading t bits of the
// full 128-bit tag -- rather than any other way of producing t bits.
func TestNewGCM_ProducesTheLeadingBitsOfTheFullTag(t *testing.T) {
	block := testBlock(t)
	nonce := make([]byte, 12)
	plaintext := []byte("truncate my tag")
	aad := []byte("aad")

	full, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	fullSealed := full.Seal(nil, nonce, plaintext, aad)
	fullTag := fullSealed[len(fullSealed)-16:]

	for _, tagSize := range []int{12, 13, 14, 15, 16} {
		t.Run(fmt.Sprintf("tagSize=%d", tagSize), func(t *testing.T) {
			gcm, err := NewGCM(block, tagSize)
			if err != nil {
				t.Fatalf("NewGCM: %v", err)
			}
			if gcm.Overhead() != tagSize {
				t.Fatalf("Overhead() = %d, want %d", gcm.Overhead(), tagSize)
			}

			sealed := gcm.Seal(nil, nonce, plaintext, aad)
			gotTag := sealed[len(sealed)-tagSize:]
			if !bytes.Equal(gotTag, fullTag[:tagSize]) {
				t.Fatalf("tag = %x, want the leading %d bytes of the full tag %x",
					gotTag, tagSize, fullTag)
			}
		})
	}
}

// TestNewGCM_ZeroSelectsTheFullTag pins the zero value's meaning: no request,
// so the cipher's own full-length tag.
func TestNewGCM_ZeroSelectsTheFullTag(t *testing.T) {
	gcm, err := NewGCM(testBlock(t), 0)
	if err != nil {
		t.Fatalf("NewGCM: %v", err)
	}
	if gcm.Overhead() != GCMFullTagSize {
		t.Fatalf("Overhead() = %d, want %d", gcm.Overhead(), GCMFullTagSize)
	}
}

// TestResolveGCMTagSize_RefusesUnapprovedLengths is the bad-input case.
// Rounding to the nearest permitted length would hand a caller a tag its peer
// cannot verify, with a success return to say it worked.
func TestResolveGCMTagSize_RefusesUnapprovedLengths(t *testing.T) {
	for _, tagSize := range []int{-8, -1, 1, 4, 8, 11, 17, 24, 32} {
		t.Run(fmt.Sprintf("tagSize=%d", tagSize), func(t *testing.T) {
			if ValidGCMTagSize(tagSize) {
				t.Fatalf("ValidGCMTagSize(%d) = true", tagSize)
			}
			if _, err := ResolveGCMTagSize(tagSize); !errors.Is(err, ErrInvalidGCMTagSize) {
				t.Fatalf("ResolveGCMTagSize(%d) error = %v, want ErrInvalidGCMTagSize", tagSize, err)
			}
			if _, err := NewGCM(testBlock(t), tagSize); !errors.Is(err, ErrInvalidGCMTagSize) {
				t.Fatalf("NewGCM(%d) error = %v, want ErrInvalidGCMTagSize", tagSize, err)
			}
		})
	}
}

// TestResolveGCMTagSize_AcceptsApprovedLengths is the success case for the
// same function.
func TestResolveGCMTagSize_AcceptsApprovedLengths(t *testing.T) {
	if got, err := ResolveGCMTagSize(0); err != nil || got != GCMFullTagSize {
		t.Fatalf("ResolveGCMTagSize(0) = %d, %v; want %d, nil", got, err, GCMFullTagSize)
	}
	for _, tagSize := range []int{12, 13, 14, 15, 16} {
		if !ValidGCMTagSize(tagSize) {
			t.Errorf("ValidGCMTagSize(%d) = false", tagSize)
		}
		got, err := ResolveGCMTagSize(tagSize)
		if err != nil || got != tagSize {
			t.Errorf("ResolveGCMTagSize(%d) = %d, %v; want %d, nil", tagSize, got, err, tagSize)
		}
	}
}

// TestRequireDefaultTagSize covers the refusal a provider uses when it does
// not choose its own tag length -- a remote KMS returning an opaque blob, or a
// cipher with no truncation construction.
func TestRequireDefaultTagSize(t *testing.T) {
	if err := RequireDefaultTagSize(0, "Test KMS"); err != nil {
		t.Fatalf("RequireDefaultTagSize(0) = %v, want nil", err)
	}

	for _, tagSize := range []int{12, 16, 99} {
		err := RequireDefaultTagSize(tagSize, "Test KMS")
		if !errors.Is(err, ErrTagSizeNotConfigurable) {
			t.Fatalf("RequireDefaultTagSize(%d) error = %v, want ErrTagSizeNotConfigurable", tagSize, err)
		}
		// The provider name has to reach the operator: with several backends
		// configured, "not configurable" alone does not say which refused.
		if !bytes.Contains([]byte(err.Error()), []byte("Test KMS")) {
			t.Fatalf("error %q does not name the provider", err)
		}
	}
}
