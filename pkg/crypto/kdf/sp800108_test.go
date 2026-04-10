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

package kdf

import (
	"bytes"
	"crypto"
	"testing"
)

func TestSP800108CounterMode_Basic(t *testing.T) {
	adapter := NewSP800108CounterAdapter()

	kdk := []byte("test-key-derivation-key-32bytes!")
	params := &KDFParams{
		Algorithm: AlgorithmSP800108Counter,
		KeyLength: 32,
		Hash:      crypto.SHA256,
		Label:     []byte("test-label"),
		Context:   []byte("test-context"),
	}

	derivedKey, err := adapter.DeriveKey(kdk, params)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	if len(derivedKey) != 32 {
		t.Errorf("expected key length 32, got %d", len(derivedKey))
	}

	// Derive again with same params - should get same result
	derivedKey2, err := adapter.DeriveKey(kdk, params)
	if err != nil {
		t.Fatalf("second DeriveKey failed: %v", err)
	}

	if !bytes.Equal(derivedKey, derivedKey2) {
		t.Error("derived keys should be deterministic")
	}
}

func TestSP800108CounterMode_DifferentParams(t *testing.T) {
	adapter := NewSP800108CounterAdapter()
	kdk := []byte("test-key-derivation-key-32bytes!")

	// Derive with first set of params
	params1 := &KDFParams{
		Algorithm: AlgorithmSP800108Counter,
		KeyLength: 32,
		Hash:      crypto.SHA256,
		Label:     []byte("label-1"),
		Context:   []byte("context-1"),
	}
	key1, err := adapter.DeriveKey(kdk, params1)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	// Derive with different label
	params2 := &KDFParams{
		Algorithm: AlgorithmSP800108Counter,
		KeyLength: 32,
		Hash:      crypto.SHA256,
		Label:     []byte("label-2"),
		Context:   []byte("context-1"),
	}
	key2, err := adapter.DeriveKey(kdk, params2)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	if bytes.Equal(key1, key2) {
		t.Error("keys with different labels should be different")
	}

	// Derive with different context
	params3 := &KDFParams{
		Algorithm: AlgorithmSP800108Counter,
		KeyLength: 32,
		Hash:      crypto.SHA256,
		Label:     []byte("label-1"),
		Context:   []byte("context-2"),
	}
	key3, err := adapter.DeriveKey(kdk, params3)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	if bytes.Equal(key1, key3) {
		t.Error("keys with different contexts should be different")
	}
}

func TestSP800108CounterMode_DifferentKeyLengths(t *testing.T) {
	adapter := NewSP800108CounterAdapter()
	kdk := []byte("test-key-derivation-key-32bytes!")

	testCases := []int{16, 32, 48, 64, 128}

	for _, keyLen := range testCases {
		params := &KDFParams{
			Algorithm: AlgorithmSP800108Counter,
			KeyLength: keyLen,
			Hash:      crypto.SHA256,
			Label:     []byte("test"),
			Context:   []byte("context"),
		}

		derivedKey, err := adapter.DeriveKey(kdk, params)
		if err != nil {
			t.Errorf("DeriveKey failed for length %d: %v", keyLen, err)
			continue
		}

		if len(derivedKey) != keyLen {
			t.Errorf("expected key length %d, got %d", keyLen, len(derivedKey))
		}
	}
}

func TestSP800108CounterMode_DifferentHashes(t *testing.T) {
	adapter := NewSP800108CounterAdapter()
	kdk := []byte("test-key-derivation-key-32bytes!")

	hashes := []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512}
	keys := make([][]byte, len(hashes))

	for i, h := range hashes {
		params := &KDFParams{
			Algorithm: AlgorithmSP800108Counter,
			KeyLength: 32,
			Hash:      h,
			Label:     []byte("test"),
			Context:   []byte("context"),
		}

		key, err := adapter.DeriveKey(kdk, params)
		if err != nil {
			t.Errorf("DeriveKey failed for hash %v: %v", h, err)
			continue
		}
		keys[i] = key
	}

	// All keys should be different
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if bytes.Equal(keys[i], keys[j]) {
				t.Errorf("keys with different hash functions should be different")
			}
		}
	}
}

func TestSP800108FeedbackMode_Basic(t *testing.T) {
	adapter := NewSP800108FeedbackAdapter()

	kdk := []byte("test-key-derivation-key-32bytes!")
	params := &KDFParams{
		Algorithm: AlgorithmSP800108Feedback,
		KeyLength: 32,
		Hash:      crypto.SHA256,
		Label:     []byte("test-label"),
		Context:   []byte("test-context"),
	}

	derivedKey, err := adapter.DeriveKey(kdk, params)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	if len(derivedKey) != 32 {
		t.Errorf("expected key length 32, got %d", len(derivedKey))
	}
}

func TestSP800108FeedbackMode_WithIV(t *testing.T) {
	adapter := NewSP800108FeedbackAdapter()
	kdk := []byte("test-key-derivation-key-32bytes!")

	// Without IV
	params1 := &KDFParams{
		Algorithm: AlgorithmSP800108Feedback,
		KeyLength: 32,
		Hash:      crypto.SHA256,
		Label:     []byte("test"),
		Context:   []byte("context"),
	}
	key1, err := adapter.DeriveKey(kdk, params1)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	// With IV
	params2 := &KDFParams{
		Algorithm: AlgorithmSP800108Feedback,
		KeyLength: 32,
		Hash:      crypto.SHA256,
		Label:     []byte("test"),
		Context:   []byte("context"),
		IV:        []byte("initial-value-16"),
	}
	key2, err := adapter.DeriveKey(kdk, params2)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	if bytes.Equal(key1, key2) {
		t.Error("keys with and without IV should be different")
	}
}

func TestSP800108DoublePipelineMode_Basic(t *testing.T) {
	adapter := NewSP800108DoublePipelineAdapter()

	kdk := []byte("test-key-derivation-key-32bytes!")
	params := &KDFParams{
		Algorithm: AlgorithmSP800108DoublePipeline,
		KeyLength: 32,
		Hash:      crypto.SHA256,
		Label:     []byte("test-label"),
		Context:   []byte("test-context"),
	}

	derivedKey, err := adapter.DeriveKey(kdk, params)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	if len(derivedKey) != 32 {
		t.Errorf("expected key length 32, got %d", len(derivedKey))
	}
}

func TestSP800108_AllModesDifferent(t *testing.T) {
	kdk := []byte("test-key-derivation-key-32bytes!")

	// Use params that require multiple iterations to see mode differences
	// With 64-byte output and SHA-256 (32-byte), we need 2 iterations
	params := &KDFParams{
		KeyLength: 64,
		Hash:      crypto.SHA256,
		Label:     []byte("test"),
		Context:   []byte("context"),
	}

	counterAdapter := NewSP800108CounterAdapter()
	feedbackAdapter := NewSP800108FeedbackAdapter()
	doublePipelineAdapter := NewSP800108DoublePipelineAdapter()

	counterKey, _ := counterAdapter.DeriveKey(kdk, params)
	feedbackKey, _ := feedbackAdapter.DeriveKey(kdk, params)
	doublePipelineKey, _ := doublePipelineAdapter.DeriveKey(kdk, params)

	// Counter and feedback modes produce different keys in multi-iteration scenarios
	// because feedback uses K(i-1) as part of the input
	if bytes.Equal(counterKey, feedbackKey) {
		t.Error("counter and feedback modes should produce different keys with multi-iteration")
	}
	if bytes.Equal(counterKey, doublePipelineKey) {
		t.Error("counter and double-pipeline modes should produce different keys")
	}
	if bytes.Equal(feedbackKey, doublePipelineKey) {
		t.Error("feedback and double-pipeline modes should produce different keys")
	}
}

func TestSP800108_ValidateParams(t *testing.T) {
	adapter := NewSP800108CounterAdapter()

	tests := []struct {
		name    string
		params  *KDFParams
		wantErr error
	}{
		{
			name:    "nil params",
			params:  nil,
			wantErr: ErrInvalidIKM,
		},
		{
			name: "zero key length",
			params: &KDFParams{
				KeyLength: 0,
				Hash:      crypto.SHA256,
			},
			wantErr: ErrInvalidKeyLength,
		},
		{
			name: "negative key length",
			params: &KDFParams{
				KeyLength: -1,
				Hash:      crypto.SHA256,
			},
			wantErr: ErrInvalidKeyLength,
		},
		{
			name: "invalid counter length",
			params: &KDFParams{
				KeyLength:     32,
				Hash:          crypto.SHA256,
				CounterLength: 12, // not 8, 16, 24, or 32
			},
			wantErr: ErrInvalidCounterLength,
		},
		{
			name: "valid 8-bit counter",
			params: &KDFParams{
				KeyLength:     32,
				Hash:          crypto.SHA256,
				CounterLength: 8,
			},
			wantErr: nil,
		},
		{
			name: "valid 16-bit counter",
			params: &KDFParams{
				KeyLength:     32,
				Hash:          crypto.SHA256,
				CounterLength: 16,
			},
			wantErr: nil,
		},
		{
			name: "valid 24-bit counter",
			params: &KDFParams{
				KeyLength:     32,
				Hash:          crypto.SHA256,
				CounterLength: 24,
			},
			wantErr: nil,
		},
		{
			name: "valid 32-bit counter",
			params: &KDFParams{
				KeyLength:     32,
				Hash:          crypto.SHA256,
				CounterLength: 32,
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := adapter.ValidateParams(tt.params)
			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("expected error %v, got %v", tt.wantErr, err)
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestSP800108_EmptyIKM(t *testing.T) {
	adapter := NewSP800108CounterAdapter()

	params := &KDFParams{
		KeyLength: 32,
		Hash:      crypto.SHA256,
		Label:     []byte("test"),
		Context:   []byte("context"),
	}

	_, err := adapter.DeriveKey(nil, params)
	if err != ErrInvalidIKM {
		t.Errorf("expected ErrInvalidIKM, got %v", err)
	}

	_, err = adapter.DeriveKey([]byte{}, params)
	if err != ErrInvalidIKM {
		t.Errorf("expected ErrInvalidIKM for empty slice, got %v", err)
	}
}

func TestSP800108_Algorithm(t *testing.T) {
	tests := []struct {
		adapter  *SP800108Adapter
		expected KDFAlgorithm
	}{
		{NewSP800108CounterAdapter(), AlgorithmSP800108Counter},
		{NewSP800108FeedbackAdapter(), AlgorithmSP800108Feedback},
		{NewSP800108DoublePipelineAdapter(), AlgorithmSP800108DoublePipeline},
	}

	for _, tt := range tests {
		if tt.adapter.Algorithm() != tt.expected {
			t.Errorf("expected algorithm %s, got %s", tt.expected, tt.adapter.Algorithm())
		}
	}
}

func TestSP800108_CounterLocation(t *testing.T) {
	adapter := NewSP800108CounterAdapter()
	kdk := []byte("test-key-derivation-key-32bytes!")

	// Counter before fixed data (default)
	params1 := &KDFParams{
		KeyLength:       32,
		Hash:            crypto.SHA256,
		Label:           []byte("test"),
		Context:         []byte("context"),
		CounterLocation: "before",
	}
	key1, _ := adapter.DeriveKey(kdk, params1)

	// Counter after fixed data
	params2 := &KDFParams{
		KeyLength:       32,
		Hash:            crypto.SHA256,
		Label:           []byte("test"),
		Context:         []byte("context"),
		CounterLocation: "after",
	}
	key2, _ := adapter.DeriveKey(kdk, params2)

	if bytes.Equal(key1, key2) {
		t.Error("different counter locations should produce different keys")
	}
}
