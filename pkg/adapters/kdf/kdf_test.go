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

package kdf

import (
	"bytes"
	"crypto"
	_ "crypto/sha256" // Link in SHA256
	_ "crypto/sha512" // Link in SHA512
	"testing"
)

// Test data
var (
	testIKM  = []byte("test input key material with sufficient entropy")
	testSalt = []byte("saltsaltsaltsalt") // 16 bytes
	testInfo = []byte("application context info")
)

// TestKDFAlgorithm_String tests the String method of KDFAlgorithm
func TestKDFAlgorithm_String(t *testing.T) {
	tests := []struct {
		name      string
		algorithm KDFAlgorithm
		want      string
	}{
		{
			name:      "HKDF",
			algorithm: AlgorithmHKDF,
			want:      "HKDF",
		},
		{
			name:      "PBKDF2",
			algorithm: AlgorithmPBKDF2,
			want:      "PBKDF2",
		},
		{
			name:      "Argon2",
			algorithm: AlgorithmArgon2,
			want:      "Argon2",
		},
		{
			name:      "Argon2i",
			algorithm: AlgorithmArgon2i,
			want:      "Argon2i",
		},
		{
			name:      "Argon2id",
			algorithm: AlgorithmArgon2id,
			want:      "Argon2id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.algorithm.String()
			if got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestDefaultParams tests the DefaultParams function
func TestDefaultParams(t *testing.T) {
	tests := []struct {
		name      string
		algorithm KDFAlgorithm
		validate  func(*testing.T, *KDFParams)
	}{
		{
			name:      "HKDF defaults",
			algorithm: AlgorithmHKDF,
			validate: func(t *testing.T, p *KDFParams) {
				if p == nil {
					t.Fatal("DefaultParams returned nil")
				}
				if p.Algorithm != AlgorithmHKDF {
					t.Errorf("Algorithm = %v, want %v", p.Algorithm, AlgorithmHKDF)
				}
				if p.KeyLength != 32 {
					t.Errorf("KeyLength = %v, want 32", p.KeyLength)
				}
				if p.Hash != crypto.SHA256 {
					t.Errorf("Hash = %v, want %v", p.Hash, crypto.SHA256)
				}
			},
		},
		{
			name:      "PBKDF2 defaults",
			algorithm: AlgorithmPBKDF2,
			validate: func(t *testing.T, p *KDFParams) {
				if p == nil {
					t.Fatal("DefaultParams returned nil")
				}
				if p.Algorithm != AlgorithmPBKDF2 {
					t.Errorf("Algorithm = %v, want %v", p.Algorithm, AlgorithmPBKDF2)
				}
				if p.Iterations != 600000 {
					t.Errorf("Iterations = %v, want 600000", p.Iterations)
				}
				if p.KeyLength != 32 {
					t.Errorf("KeyLength = %v, want 32", p.KeyLength)
				}
				if p.Hash != crypto.SHA256 {
					t.Errorf("Hash = %v, want %v", p.Hash, crypto.SHA256)
				}
			},
		},
		{
			name:      "Argon2id defaults",
			algorithm: AlgorithmArgon2id,
			validate: func(t *testing.T, p *KDFParams) {
				if p == nil {
					t.Fatal("DefaultParams returned nil")
				}
				if p.Algorithm != AlgorithmArgon2id {
					t.Errorf("Algorithm = %v, want %v", p.Algorithm, AlgorithmArgon2id)
				}
				if p.Memory != 64*1024 {
					t.Errorf("Memory = %v, want 65536", p.Memory)
				}
				if p.Time != 3 {
					t.Errorf("Time = %v, want 3", p.Time)
				}
				if p.Threads != 4 {
					t.Errorf("Threads = %v, want 4", p.Threads)
				}
				if p.KeyLength != 32 {
					t.Errorf("KeyLength = %v, want 32", p.KeyLength)
				}
			},
		},
		{
			name:      "Argon2i defaults",
			algorithm: AlgorithmArgon2i,
			validate: func(t *testing.T, p *KDFParams) {
				if p == nil {
					t.Fatal("DefaultParams returned nil")
				}
				if p.Algorithm != AlgorithmArgon2i {
					t.Errorf("Algorithm = %v, want %v", p.Algorithm, AlgorithmArgon2i)
				}
			},
		},
		{
			name:      "Argon2 generic defaults to Argon2id",
			algorithm: AlgorithmArgon2,
			validate: func(t *testing.T, p *KDFParams) {
				if p == nil {
					t.Fatal("DefaultParams returned nil")
				}
				if p.Algorithm != AlgorithmArgon2id {
					t.Errorf("Algorithm = %v, want %v", p.Algorithm, AlgorithmArgon2id)
				}
			},
		},
		{
			name:      "Unknown algorithm returns nil",
			algorithm: KDFAlgorithm("unknown"),
			validate: func(t *testing.T, p *KDFParams) {
				if p != nil {
					t.Errorf("DefaultParams = %v, want nil", p)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := DefaultParams(tt.algorithm)
			tt.validate(t, params)
		})
	}
}

// TestHKDFAdapter_DeriveKey tests HKDF key derivation
func TestHKDFAdapter_DeriveKey(t *testing.T) {
	adapter := NewHKDFAdapter()

	tests := []struct {
		name    string
		ikm     []byte
		params  *KDFParams
		wantErr error
	}{
		{
			name: "valid derivation with salt and info",
			ikm:  testIKM,
			params: &KDFParams{
				Algorithm: AlgorithmHKDF,
				Salt:      testSalt,
				Info:      testInfo,
				KeyLength: 32,
				Hash:      crypto.SHA256,
			},
			wantErr: nil,
		},
		{
			name: "valid derivation without salt",
			ikm:  testIKM,
			params: &KDFParams{
				Algorithm: AlgorithmHKDF,
				Info:      testInfo,
				KeyLength: 32,
				Hash:      crypto.SHA256,
			},
			wantErr: nil,
		},
		{
			name: "valid derivation without info",
			ikm:  testIKM,
			params: &KDFParams{
				Algorithm: AlgorithmHKDF,
				Salt:      testSalt,
				KeyLength: 32,
				Hash:      crypto.SHA256,
			},
			wantErr: nil,
		},
		{
			name: "valid derivation with SHA512",
			ikm:  testIKM,
			params: &KDFParams{
				Algorithm: AlgorithmHKDF,
				Salt:      testSalt,
				Info:      testInfo,
				KeyLength: 64,
				Hash:      crypto.SHA512,
			},
			wantErr: nil,
		},
		{
			name: "empty IKM",
			ikm:  []byte{},
			params: &KDFParams{
				Algorithm: AlgorithmHKDF,
				Salt:      testSalt,
				KeyLength: 32,
				Hash:      crypto.SHA256,
			},
			wantErr: ErrInvalidIKM,
		},
		{
			name: "invalid key length (zero)",
			ikm:  testIKM,
			params: &KDFParams{
				Algorithm: AlgorithmHKDF,
				Salt:      testSalt,
				KeyLength: 0,
				Hash:      crypto.SHA256,
			},
			wantErr: ErrInvalidKeyLength,
		},
		{
			name: "invalid key length (too large)",
			ikm:  testIKM,
			params: &KDFParams{
				Algorithm: AlgorithmHKDF,
				Salt:      testSalt,
				KeyLength: 256 * 32, // Exceeds 255 * hash size
				Hash:      crypto.SHA256,
			},
			wantErr: ErrInvalidKeyLength,
		},
		{
			name: "wrong algorithm",
			ikm:  testIKM,
			params: &KDFParams{
				Algorithm: AlgorithmPBKDF2,
				Salt:      testSalt,
				KeyLength: 32,
				Hash:      crypto.SHA256,
			},
			wantErr: ErrUnsupportedAlgorithm,
		},
		{
			name: "invalid hash (zero value)",
			ikm:  testIKM,
			params: &KDFParams{
				Algorithm: AlgorithmHKDF,
				Salt:      testSalt,
				KeyLength: 32,
				Hash:      0, // Zero value hash
			},
			wantErr: ErrInvalidHash,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := adapter.DeriveKey(tt.ikm, tt.params)

			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("DeriveKey() error = nil, want %v", tt.wantErr)
				} else if err != tt.wantErr {
					t.Errorf("DeriveKey() error = %v, want %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Errorf("DeriveKey() unexpected error = %v", err)
				return
			}

			if len(key) != tt.params.KeyLength {
				t.Errorf("key length = %v, want %v", len(key), tt.params.KeyLength)
			}
		})
	}
}

// TestHKDFAdapter_Deterministic tests that HKDF produces deterministic results
func TestHKDFAdapter_Deterministic(t *testing.T) {
	adapter := NewHKDFAdapter()

	params := &KDFParams{
		Algorithm: AlgorithmHKDF,
		Salt:      testSalt,
		Info:      testInfo,
		KeyLength: 32,
		Hash:      crypto.SHA256,
	}

	key1, err := adapter.DeriveKey(testIKM, params)
	if err != nil {
		t.Fatalf("First derivation failed: %v", err)
	}

	key2, err := adapter.DeriveKey(testIKM, params)
	if err != nil {
		t.Fatalf("Second derivation failed: %v", err)
	}

	if !bytes.Equal(key1, key2) {
		t.Error("HKDF is not deterministic - same inputs produced different outputs")
	}
}

// TestHKDFAdapter_DifferentInputs tests that different inputs produce different outputs
func TestHKDFAdapter_DifferentInputs(t *testing.T) {
	adapter := NewHKDFAdapter()

	params := &KDFParams{
		Algorithm: AlgorithmHKDF,
		Salt:      testSalt,
		Info:      testInfo,
		KeyLength: 32,
		Hash:      crypto.SHA256,
	}

	key1, err := adapter.DeriveKey(testIKM, params)
	if err != nil {
		t.Fatalf("First derivation failed: %v", err)
	}

	differentIKM := []byte("different input key material")
	key2, err := adapter.DeriveKey(differentIKM, params)
	if err != nil {
		t.Fatalf("Second derivation failed: %v", err)
	}

	if bytes.Equal(key1, key2) {
		t.Error("Different IKM produced same output")
	}
}

// TestHKDFAdapter_Algorithm tests the Algorithm method
func TestHKDFAdapter_Algorithm(t *testing.T) {
	adapter := NewHKDFAdapter()
	if adapter.Algorithm() != AlgorithmHKDF {
		t.Errorf("Algorithm() = %v, want %v", adapter.Algorithm(), AlgorithmHKDF)
	}
}

// TestPBKDF2Adapter_DeriveKey tests PBKDF2 key derivation
func TestPBKDF2Adapter_DeriveKey(t *testing.T) {
	adapter := NewPBKDF2Adapter()

	tests := []struct {
		name    string
		ikm     []byte
		params  *KDFParams
		wantErr error
	}{
		{
			name: "valid derivation with SHA256",
			ikm:  testIKM,
			params: &KDFParams{
				Algorithm:  AlgorithmPBKDF2,
				Salt:       testSalt,
				Iterations: 100000,
				KeyLength:  32,
				Hash:       crypto.SHA256,
			},
			wantErr: nil,
		},
		{
			name: "valid derivation with SHA512",
			ikm:  testIKM,
			params: &KDFParams{
				Algorithm:  AlgorithmPBKDF2,
				Salt:       testSalt,
				Iterations: 100000,
				KeyLength:  64,
				Hash:       crypto.SHA512,
			},
			wantErr: nil,
		},
		{
			name: "empty IKM",
			ikm:  []byte{},
			params: &KDFParams{
				Algorithm:  AlgorithmPBKDF2,
				Salt:       testSalt,
				Iterations: 100000,
				KeyLength:  32,
				Hash:       crypto.SHA256,
			},
			wantErr: ErrInvalidIKM,
		},
		{
			name: "salt too short",
			ikm:  testIKM,
			params: &KDFParams{
				Algorithm:  AlgorithmPBKDF2,
				Salt:       []byte("short"),
				Iterations: 100000,
				KeyLength:  32,
				Hash:       crypto.SHA256,
			},
			wantErr: ErrInvalidSalt,
		},
		{
			name: "iterations too low",
			ikm:  testIKM,
			params: &KDFParams{
				Algorithm:  AlgorithmPBKDF2,
				Salt:       testSalt,
				Iterations: 1000,
				KeyLength:  32,
				Hash:       crypto.SHA256,
			},
			wantErr: ErrInvalidIterations,
		},
		{
			name: "invalid key length",
			ikm:  testIKM,
			params: &KDFParams{
				Algorithm:  AlgorithmPBKDF2,
				Salt:       testSalt,
				Iterations: 100000,
				KeyLength:  0,
				Hash:       crypto.SHA256,
			},
			wantErr: ErrInvalidKeyLength,
		},
		{
			name: "wrong algorithm",
			ikm:  testIKM,
			params: &KDFParams{
				Algorithm:  AlgorithmHKDF,
				Salt:       testSalt,
				Iterations: 100000,
				KeyLength:  32,
				Hash:       crypto.SHA256,
			},
			wantErr: ErrUnsupportedAlgorithm,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := adapter.DeriveKey(tt.ikm, tt.params)

			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("DeriveKey() error = nil, want %v", tt.wantErr)
				} else if err != tt.wantErr {
					t.Errorf("DeriveKey() error = %v, want %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Errorf("DeriveKey() unexpected error = %v", err)
				return
			}

			if len(key) != tt.params.KeyLength {
				t.Errorf("key length = %v, want %v", len(key), tt.params.KeyLength)
			}
		})
	}
}

// TestPBKDF2Adapter_Deterministic tests that PBKDF2 produces deterministic results
func TestPBKDF2Adapter_Deterministic(t *testing.T) {
	adapter := NewPBKDF2Adapter()

	params := &KDFParams{
		Algorithm:  AlgorithmPBKDF2,
		Salt:       testSalt,
		Iterations: 100000,
		KeyLength:  32,
		Hash:       crypto.SHA256,
	}

	key1, err := adapter.DeriveKey(testIKM, params)
	if err != nil {
		t.Fatalf("First derivation failed: %v", err)
	}

	key2, err := adapter.DeriveKey(testIKM, params)
	if err != nil {
		t.Fatalf("Second derivation failed: %v", err)
	}

	if !bytes.Equal(key1, key2) {
		t.Error("PBKDF2 is not deterministic - same inputs produced different outputs")
	}
}

// TestPBKDF2Adapter_Algorithm tests the Algorithm method
func TestPBKDF2Adapter_Algorithm(t *testing.T) {
	adapter := NewPBKDF2Adapter()
	if adapter.Algorithm() != AlgorithmPBKDF2 {
		t.Errorf("Algorithm() = %v, want %v", adapter.Algorithm(), AlgorithmPBKDF2)
	}
}

// TestArgon2Adapter_DeriveKey tests Argon2 key derivation
func TestArgon2Adapter_DeriveKey(t *testing.T) {
	tests := []struct {
		name    string
		adapter KDFAdapter
		ikm     []byte
		params  *KDFParams
		wantErr error
	}{
		{
			name:    "valid Argon2id derivation",
			adapter: NewArgon2idAdapter(),
			ikm:     testIKM,
			params: &KDFParams{
				Algorithm: AlgorithmArgon2id,
				Salt:      testSalt,
				Memory:    64 * 1024,
				Time:      3,
				Threads:   4,
				KeyLength: 32,
			},
			wantErr: nil,
		},
		{
			name:    "valid Argon2i derivation",
			adapter: NewArgon2iAdapter(),
			ikm:     testIKM,
			params: &KDFParams{
				Algorithm: AlgorithmArgon2i,
				Salt:      testSalt,
				Memory:    64 * 1024,
				Time:      3,
				Threads:   4,
				KeyLength: 32,
			},
			wantErr: nil,
		},
		{
			name:    "generic Argon2 algorithm with Argon2id adapter",
			adapter: NewArgon2idAdapter(),
			ikm:     testIKM,
			params: &KDFParams{
				Algorithm: AlgorithmArgon2,
				Salt:      testSalt,
				Memory:    64 * 1024,
				Time:      3,
				Threads:   4,
				KeyLength: 32,
			},
			wantErr: nil,
		},
		{
			name:    "empty IKM",
			adapter: NewArgon2idAdapter(),
			ikm:     []byte{},
			params: &KDFParams{
				Algorithm: AlgorithmArgon2id,
				Salt:      testSalt,
				Memory:    64 * 1024,
				Time:      3,
				Threads:   4,
				KeyLength: 32,
			},
			wantErr: ErrInvalidIKM,
		},
		{
			name:    "salt too short",
			adapter: NewArgon2idAdapter(),
			ikm:     testIKM,
			params: &KDFParams{
				Algorithm: AlgorithmArgon2id,
				Salt:      []byte("short"),
				Memory:    64 * 1024,
				Time:      3,
				Threads:   4,
				KeyLength: 32,
			},
			wantErr: ErrInvalidSalt,
		},
		{
			name:    "memory too low",
			adapter: NewArgon2idAdapter(),
			ikm:     testIKM,
			params: &KDFParams{
				Algorithm: AlgorithmArgon2id,
				Salt:      testSalt,
				Memory:    1024, // Less than 8 MiB
				Time:      3,
				Threads:   4,
				KeyLength: 32,
			},
			wantErr: ErrInvalidMemory,
		},
		{
			name:    "time too low",
			adapter: NewArgon2idAdapter(),
			ikm:     testIKM,
			params: &KDFParams{
				Algorithm: AlgorithmArgon2id,
				Salt:      testSalt,
				Memory:    64 * 1024,
				Time:      0,
				Threads:   4,
				KeyLength: 32,
			},
			wantErr: ErrInvalidTime,
		},
		{
			name:    "threads too low",
			adapter: NewArgon2idAdapter(),
			ikm:     testIKM,
			params: &KDFParams{
				Algorithm: AlgorithmArgon2id,
				Salt:      testSalt,
				Memory:    64 * 1024,
				Time:      3,
				Threads:   0,
				KeyLength: 32,
			},
			wantErr: ErrInvalidThreads,
		},
		{
			name:    "invalid key length",
			adapter: NewArgon2idAdapter(),
			ikm:     testIKM,
			params: &KDFParams{
				Algorithm: AlgorithmArgon2id,
				Salt:      testSalt,
				Memory:    64 * 1024,
				Time:      3,
				Threads:   4,
				KeyLength: 0,
			},
			wantErr: ErrInvalidKeyLength,
		},
		{
			name:    "wrong algorithm for adapter",
			adapter: NewArgon2idAdapter(),
			ikm:     testIKM,
			params: &KDFParams{
				Algorithm: AlgorithmPBKDF2,
				Salt:      testSalt,
				Memory:    64 * 1024,
				Time:      3,
				Threads:   4,
				KeyLength: 32,
			},
			wantErr: ErrUnsupportedAlgorithm,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := tt.adapter.DeriveKey(tt.ikm, tt.params)

			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("DeriveKey() error = nil, want %v", tt.wantErr)
				} else if err != tt.wantErr {
					t.Errorf("DeriveKey() error = %v, want %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Errorf("DeriveKey() unexpected error = %v", err)
				return
			}

			if len(key) != tt.params.KeyLength {
				t.Errorf("key length = %v, want %v", len(key), tt.params.KeyLength)
			}
		})
	}
}

// TestArgon2Adapter_Deterministic tests that Argon2 produces deterministic results
func TestArgon2Adapter_Deterministic(t *testing.T) {
	tests := []struct {
		name    string
		adapter KDFAdapter
		params  *KDFParams
	}{
		{
			name:    "Argon2id deterministic",
			adapter: NewArgon2idAdapter(),
			params: &KDFParams{
				Algorithm: AlgorithmArgon2id,
				Salt:      testSalt,
				Memory:    64 * 1024,
				Time:      3,
				Threads:   4,
				KeyLength: 32,
			},
		},
		{
			name:    "Argon2i deterministic",
			adapter: NewArgon2iAdapter(),
			params: &KDFParams{
				Algorithm: AlgorithmArgon2i,
				Salt:      testSalt,
				Memory:    64 * 1024,
				Time:      3,
				Threads:   4,
				KeyLength: 32,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key1, err := tt.adapter.DeriveKey(testIKM, tt.params)
			if err != nil {
				t.Fatalf("First derivation failed: %v", err)
			}

			key2, err := tt.adapter.DeriveKey(testIKM, tt.params)
			if err != nil {
				t.Fatalf("Second derivation failed: %v", err)
			}

			if !bytes.Equal(key1, key2) {
				t.Errorf("Argon2 is not deterministic - same inputs produced different outputs")
			}
		})
	}
}

// TestArgon2Adapter_Algorithm tests the Algorithm method
func TestArgon2Adapter_Algorithm(t *testing.T) {
	tests := []struct {
		name    string
		adapter KDFAdapter
		want    KDFAlgorithm
	}{
		{
			name:    "Argon2id adapter",
			adapter: NewArgon2idAdapter(),
			want:    AlgorithmArgon2id,
		},
		{
			name:    "Argon2i adapter",
			adapter: NewArgon2iAdapter(),
			want:    AlgorithmArgon2i,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.adapter.Algorithm(); got != tt.want {
				t.Errorf("Algorithm() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestArgon2Adapter_VariantSelection tests that the adapter uses the correct variant
func TestArgon2Adapter_VariantSelection(t *testing.T) {
	tests := []struct {
		name    string
		variant KDFAlgorithm
		want    KDFAlgorithm
	}{
		{
			name:    "Argon2id variant",
			variant: AlgorithmArgon2id,
			want:    AlgorithmArgon2id,
		},
		{
			name:    "Argon2i variant",
			variant: AlgorithmArgon2i,
			want:    AlgorithmArgon2i,
		},
		{
			name:    "Invalid variant defaults to Argon2id",
			variant: KDFAlgorithm("invalid"),
			want:    AlgorithmArgon2id,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter := NewArgon2Adapter(tt.variant)
			if got := adapter.Algorithm(); got != tt.want {
				t.Errorf("Algorithm() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestValidateParams tests parameter validation for all adapters
func TestValidateParams(t *testing.T) {
	tests := []struct {
		name    string
		adapter KDFAdapter
		params  *KDFParams
		wantErr error
	}{
		{
			name:    "HKDF nil params",
			adapter: NewHKDFAdapter(),
			params:  nil,
			wantErr: ErrInvalidKeyLength,
		},
		{
			name:    "PBKDF2 nil params",
			adapter: NewPBKDF2Adapter(),
			params:  nil,
			wantErr: ErrInvalidKeyLength,
		},
		{
			name:    "Argon2 nil params",
			adapter: NewArgon2idAdapter(),
			params:  nil,
			wantErr: ErrInvalidKeyLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.adapter.ValidateParams(tt.params)
			if err != tt.wantErr {
				t.Errorf("ValidateParams() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestCrossAlgorithmComparison ensures different algorithms produce different outputs
func TestCrossAlgorithmComparison(t *testing.T) {
	hkdfAdapter := NewHKDFAdapter()
	pbkdf2Adapter := NewPBKDF2Adapter()
	argon2Adapter := NewArgon2idAdapter()

	hkdfParams := &KDFParams{
		Algorithm: AlgorithmHKDF,
		Salt:      testSalt,
		KeyLength: 32,
		Hash:      crypto.SHA256,
	}

	pbkdf2Params := &KDFParams{
		Algorithm:  AlgorithmPBKDF2,
		Salt:       testSalt,
		Iterations: 100000,
		KeyLength:  32,
		Hash:       crypto.SHA256,
	}

	argon2Params := &KDFParams{
		Algorithm: AlgorithmArgon2id,
		Salt:      testSalt,
		Memory:    64 * 1024,
		Time:      3,
		Threads:   4,
		KeyLength: 32,
	}

	hkdfKey, err := hkdfAdapter.DeriveKey(testIKM, hkdfParams)
	if err != nil {
		t.Fatalf("HKDF derivation failed: %v", err)
	}

	pbkdf2Key, err := pbkdf2Adapter.DeriveKey(testIKM, pbkdf2Params)
	if err != nil {
		t.Fatalf("PBKDF2 derivation failed: %v", err)
	}

	argon2Key, err := argon2Adapter.DeriveKey(testIKM, argon2Params)
	if err != nil {
		t.Fatalf("Argon2 derivation failed: %v", err)
	}

	// All keys should be different
	if bytes.Equal(hkdfKey, pbkdf2Key) {
		t.Error("HKDF and PBKDF2 produced same output")
	}

	if bytes.Equal(hkdfKey, argon2Key) {
		t.Error("HKDF and Argon2 produced same output")
	}

	if bytes.Equal(pbkdf2Key, argon2Key) {
		t.Error("PBKDF2 and Argon2 produced same output")
	}
}

// BenchmarkHKDF benchmarks HKDF performance
func BenchmarkHKDF(b *testing.B) {
	adapter := NewHKDFAdapter()
	params := &KDFParams{
		Algorithm: AlgorithmHKDF,
		Salt:      testSalt,
		Info:      testInfo,
		KeyLength: 32,
		Hash:      crypto.SHA256,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = adapter.DeriveKey(testIKM, params)
	}
}

// BenchmarkPBKDF2 benchmarks PBKDF2 performance
func BenchmarkPBKDF2(b *testing.B) {
	adapter := NewPBKDF2Adapter()
	params := &KDFParams{
		Algorithm:  AlgorithmPBKDF2,
		Salt:       testSalt,
		Iterations: 100000,
		KeyLength:  32,
		Hash:       crypto.SHA256,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = adapter.DeriveKey(testIKM, params)
	}
}

// BenchmarkArgon2id benchmarks Argon2id performance
func BenchmarkArgon2id(b *testing.B) {
	adapter := NewArgon2idAdapter()
	params := &KDFParams{
		Algorithm: AlgorithmArgon2id,
		Salt:      testSalt,
		Memory:    64 * 1024,
		Time:      3,
		Threads:   4,
		KeyLength: 32,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = adapter.DeriveKey(testIKM, params)
	}
}

// BenchmarkArgon2i benchmarks Argon2i performance
func BenchmarkArgon2i(b *testing.B) {
	adapter := NewArgon2iAdapter()
	params := &KDFParams{
		Algorithm: AlgorithmArgon2i,
		Salt:      testSalt,
		Memory:    64 * 1024,
		Time:      3,
		Threads:   4,
		KeyLength: 32,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = adapter.DeriveKey(testIKM, params)
	}
}
