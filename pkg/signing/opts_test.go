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

package signing

import (
	"crypto"
	"crypto/rsa"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// TestNewSignerOpts tests the creation of SignerOpts
func TestNewSignerOpts(t *testing.T) {
	opts := NewSignerOpts(crypto.SHA256)
	if opts == nil {
		t.Fatal("NewSignerOpts returned nil")
		return
	}
	if opts.Hash != crypto.SHA256 {
		t.Errorf("Hash mismatch: got %v, want %v", opts.Hash, crypto.SHA256)
	}
}

// TestSignerOptsHashFunc tests the HashFunc method
func TestSignerOptsHashFunc(t *testing.T) {
	tests := []struct {
		name string
		hash crypto.Hash
	}{
		{"SHA256", crypto.SHA256},
		{"SHA384", crypto.SHA384},
		{"SHA512", crypto.SHA512},
		{"SHA1", crypto.SHA1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &SignerOpts{Hash: tt.hash}
			if got := opts.HashFunc(); got != tt.hash {
				t.Errorf("HashFunc() = %v, want %v", got, tt.hash)
			}
		})
	}
}

// TestSignerOptsWithBlobCN tests the WithBlobCN method
func TestSignerOptsWithBlobCN(t *testing.T) {
	opts := NewSignerOpts(crypto.SHA256)
	cn := "test-blob"

	result := opts.WithBlobCN(cn)
	if result.BlobCN != cn {
		t.Errorf("BlobCN mismatch: got %q, want %q", result.BlobCN, cn)
	}
	if result != opts {
		t.Error("WithBlobCN did not return same instance")
	}
}

// TestSignerOptsWithBlobData tests the WithBlobData method
func TestSignerOptsWithBlobData(t *testing.T) {
	opts := NewSignerOpts(crypto.SHA256)
	data := []byte("test data")

	result := opts.WithBlobData(data)
	if string(result.BlobData) != string(data) {
		t.Errorf("BlobData mismatch: got %q, want %q", result.BlobData, data)
	}
	if result != opts {
		t.Error("WithBlobData did not return same instance")
	}
}

// TestSignerOptsWithKeyAttributes tests the WithKeyAttributes method
func TestSignerOptsWithKeyAttributes(t *testing.T) {
	opts := NewSignerOpts(crypto.SHA256)
	attrs := &types.KeyAttributes{
		CN: "test-key",
	}

	result := opts.WithKeyAttributes(attrs)
	if result.KeyAttributes != attrs {
		t.Error("KeyAttributes mismatch")
	}
	if result != opts {
		t.Error("WithKeyAttributes did not return same instance")
	}
}

// TestSignerOptsWithPSSOptions tests the WithPSSOptions method
func TestSignerOptsWithPSSOptions(t *testing.T) {
	opts := NewSignerOpts(crypto.SHA256)
	pssOpts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	}

	result := opts.WithPSSOptions(pssOpts)
	if result.PSSOptions != pssOpts {
		t.Error("PSSOptions mismatch")
	}
	if result != opts {
		t.Error("WithPSSOptions did not return same instance")
	}
}

// TestSignerOptsIsPSS tests the IsPSS method
func TestSignerOptsIsPSS(t *testing.T) {
	tests := []struct {
		name       string
		pssOptions *rsa.PSSOptions
		want       bool
	}{
		{
			name:       "with PSS options",
			pssOptions: &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto},
			want:       true,
		},
		{
			name:       "without PSS options",
			pssOptions: nil,
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &SignerOpts{
				Hash:       crypto.SHA256,
				PSSOptions: tt.pssOptions,
			}
			if got := opts.IsPSS(); got != tt.want {
				t.Errorf("IsPSS() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestSignerOptsGetDigest tests the GetDigest method
func TestSignerOptsGetDigest(t *testing.T) {
	precomputed := []byte("precomputed digest")
	blobData := []byte("test data to hash")

	tests := []struct {
		name        string
		opts        *SignerOpts
		precomputed []byte
		wantErr     bool
	}{
		{
			name: "with blob data",
			opts: &SignerOpts{
				Hash:     crypto.SHA256,
				BlobData: blobData,
			},
			precomputed: precomputed,
			wantErr:     false,
		},
		{
			name: "without blob data",
			opts: &SignerOpts{
				Hash: crypto.SHA256,
			},
			precomputed: precomputed,
			wantErr:     false,
		},
		{
			name: "with blob data and invalid hash",
			opts: &SignerOpts{
				Hash:     crypto.Hash(999),
				BlobData: blobData,
			},
			precomputed: precomputed,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			digest, err := tt.opts.GetDigest(tt.precomputed)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(digest) == 0 {
				t.Error("expected non-empty digest")
			}

			// If blob data was set, verify the digest is computed correctly
			if tt.opts.BlobData != nil {
				hasher := tt.opts.Hash.New()
				hasher.Write(tt.opts.BlobData)
				expected := hasher.Sum(nil)
				if string(digest) != string(expected) {
					t.Error("digest mismatch")
				}
			} else {
				// Otherwise, it should return the precomputed digest
				if string(digest) != string(tt.precomputed) {
					t.Error("expected precomputed digest")
				}
			}
		})
	}
}

// TestSignerOptsChaining tests method chaining
func TestSignerOptsChaining(t *testing.T) {
	attrs := &types.KeyAttributes{CN: "test-key"}
	pssOpts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}

	opts := NewSignerOpts(crypto.SHA256).
		WithBlobCN("test-blob").
		WithBlobData([]byte("test data")).
		WithKeyAttributes(attrs).
		WithPSSOptions(pssOpts)

	if opts.Hash != crypto.SHA256 {
		t.Error("Hash not set correctly")
	}
	if opts.BlobCN != "test-blob" {
		t.Error("BlobCN not set correctly")
	}
	if string(opts.BlobData) != "test data" {
		t.Error("BlobData not set correctly")
	}
	if opts.KeyAttributes != attrs {
		t.Error("KeyAttributes not set correctly")
	}
	if opts.PSSOptions != pssOpts {
		t.Error("PSSOptions not set correctly")
	}
}

// TestSignerOptsGetDigestEmptyData tests GetDigest with empty data
func TestSignerOptsGetDigestEmptyData(t *testing.T) {
	opts := &SignerOpts{
		Hash:     crypto.SHA256,
		BlobData: []byte{},
	}

	digest, err := opts.GetDigest(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(digest) == 0 {
		t.Error("expected non-empty digest even for empty data")
	}

	// Verify it's the hash of empty data
	hasher := crypto.SHA256.New()
	hasher.Write([]byte{})
	expected := hasher.Sum(nil)
	if string(digest) != string(expected) {
		t.Error("digest mismatch for empty data")
	}
}

// TestSignerOptsGetDigestNilPrecomputed tests GetDigest with nil precomputed
func TestSignerOptsGetDigestNilPrecomputed(t *testing.T) {
	opts := &SignerOpts{
		Hash: crypto.SHA256,
	}

	digest, err := opts.GetDigest(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if digest != nil {
		t.Error("expected nil digest when no blob data and precomputed is nil")
	}
}

// TestSignerOptsMultipleHashes tests GetDigest with different hash functions
func TestSignerOptsMultipleHashes(t *testing.T) {
	blobData := []byte("test data")

	tests := []struct {
		name string
		hash crypto.Hash
	}{
		{"SHA256", crypto.SHA256},
		{"SHA384", crypto.SHA384},
		{"SHA512", crypto.SHA512},
		{"SHA1", crypto.SHA1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &SignerOpts{
				Hash:     tt.hash,
				BlobData: blobData,
			}

			digest, err := opts.GetDigest(nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Verify digest is correct for the hash function
			hasher := tt.hash.New()
			hasher.Write(blobData)
			expected := hasher.Sum(nil)
			if string(digest) != string(expected) {
				t.Errorf("digest mismatch for %s", tt.name)
			}
		})
	}
}
