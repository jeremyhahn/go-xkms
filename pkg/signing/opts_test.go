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

package signing

import (
	"crypto"
	"crypto/rsa"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

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
			name: "with empty blob data",
			opts: &SignerOpts{
				Hash:     crypto.SHA256,
				BlobData: []byte{},
			},
			wantErr: false,
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

// TestSignerOptsGetDigestEmptyData tests GetDigest with empty data
