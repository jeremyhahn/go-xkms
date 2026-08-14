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

package types

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/kdf"
	"golang.org/x/crypto/hkdf"
)

// The convergence anchors below are the reference outputs every backend must
// reproduce. Their correctness comes from the CAVP suite in
// pkg/crypto/kdf/sp800108_test.go; their job here is to prove that four
// backends derive the same bytes and to freeze those bytes against a silent
// change. They are asserted here and, byte for byte, in the ECDH tests of
// pkg/backend/tpm2, pkg/backend/software, pkg/backend/pkcs11, and
// pkg/backend/phone. Four backends agreeing on a literal is what proves they
// share one implementation rather than four that happen to be close.
//
// Inputs: sharedSecret = 32 bytes of 0x42, Label = "xkms-convergence",
// Context = "backend-parity", SHA-256, 64-byte output. The length spans two
// SHA-256 PRF blocks so that counter mode and feedback mode diverge: with a
// single block and an empty K(0) the two constructions coincide, which would
// make a 32-byte anchor unable to tell them apart.
const (
	convergenceSharedSecretByte = 0x42
	convergenceLabel            = "xkms-convergence"
	convergenceContext          = "backend-parity"
	convergenceKeyLength        = 64

	// convergenceSP800108Counter is SP 800-108r1 Counter Mode with the
	// default 32-bit counter placed before the fixed input data.
	convergenceSP800108Counter = "b2b1c48c1f3282fe4be0e659653963733359b841e176e7bd39dac36bc31a7a37" +
		"79bc86106be0de29d2a74eb0b87ba4a0e2de5da0150c7e2a2c56c3a957e7e855"

	// convergenceSP800108Feedback is SP 800-108r1 Feedback Mode with an empty
	// K(0) and the default 32-bit counter.
	convergenceSP800108Feedback = "b2b1c48c1f3282fe4be0e659653963733359b841e176e7bd39dac36bc31a7a37" +
		"08ef3fb21ccf13af443722edfd6a91bc9c0b7286da80d4b269ee2156590d0706"
)

// convergenceSecret returns the shared secret the convergence anchors use.
func convergenceSecret() []byte {
	return bytes.Repeat([]byte{convergenceSharedSecretByte}, 32)
}

// convergenceParams returns the KDF parameters the convergence anchors use.
func convergenceParams(algorithm KDFAlgorithm) *KDFParams {
	return &KDFParams{
		Algorithm: algorithm,
		Hash:      "SHA-256",
		KeyLength: convergenceKeyLength,
		Label:     []byte(convergenceLabel),
		Context:   []byte(convergenceContext),
	}
}

// TestDerive_ConvergenceAnchors pins the reference bytes the backend tests
// assert against. If this test and the backend tests disagree, the backends
// have stopped sharing one KDF.
func TestDerive_ConvergenceAnchors(t *testing.T) {
	tests := []struct {
		algorithm KDFAlgorithm
		want      string
	}{
		{KDFAlgorithmSP800108Counter, convergenceSP800108Counter},
		{KDFAlgorithmSP800108Feedback, convergenceSP800108Feedback},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm.String(), func(t *testing.T) {
			got, err := convergenceParams(tt.algorithm).Derive(convergenceSecret())
			if err != nil {
				t.Fatalf("Derive: %v", err)
			}
			want, err := hex.DecodeString(tt.want)
			if err != nil {
				t.Fatalf("decoding anchor: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("convergence anchor mismatch\n got: %x\nwant: %x", got, want)
			}
		})
	}
}

// TestDerive_SP800108IsNotHKDF is the regression that catches the defect this
// bridge was written to fix: the SP 800-108 labels used to derive with HKDF.
func TestDerive_SP800108IsNotHKDF(t *testing.T) {
	secret := convergenceSecret()

	// Reproduce what the old implementation did, including its habit of
	// feeding Salt and Info straight to HKDF.
	hkdfKey := make([]byte, convergenceKeyLength)
	if _, err := io.ReadFull(hkdf.New(sha256.New, secret, []byte("salt"), []byte("info")), hkdfKey); err != nil {
		t.Fatalf("hkdf: %v", err)
	}
	bareHKDF := make([]byte, convergenceKeyLength)
	if _, err := io.ReadFull(hkdf.New(sha256.New, secret, nil, nil), bareHKDF); err != nil {
		t.Fatalf("hkdf: %v", err)
	}

	for _, algorithm := range []KDFAlgorithm{KDFAlgorithmSP800108Counter, KDFAlgorithmSP800108Feedback} {
		t.Run(algorithm.String(), func(t *testing.T) {
			derived, err := convergenceParams(algorithm).Derive(secret)
			if err != nil {
				t.Fatalf("Derive: %v", err)
			}
			if bytes.Equal(derived, hkdfKey) || bytes.Equal(derived, bareHKDF) {
				t.Errorf("%s derived the HKDF output; the SP 800-108 construction has regressed", algorithm)
			}
		})
	}
}

// TestDerive_MatchesCanonicalAdapter proves the bridge forwards every
// parameter to the canonical adapter rather than reinterpreting any of them.
func TestDerive_MatchesCanonicalAdapter(t *testing.T) {
	secret := bytes.Repeat([]byte{0x11}, 32)

	tests := []struct {
		name    string
		params  *KDFParams
		adapter kdf.KDFAdapter
		expect  *kdf.KDFParams
	}{
		{
			name: "HKDF",
			params: &KDFParams{
				Algorithm: KDFAlgorithmHKDF,
				Hash:      "SHA-384",
				KeyLength: 48,
				Salt:      []byte("salt"),
				Info:      []byte("info"),
			},
			adapter: kdf.NewHKDFAdapter(),
			expect: &kdf.KDFParams{
				Algorithm: kdf.AlgorithmHKDF,
				Hash:      crypto.SHA384,
				KeyLength: 48,
				Salt:      []byte("salt"),
				Info:      []byte("info"),
			},
		},
		{
			name: "SP800-108 counter with every knob set",
			params: &KDFParams{
				Algorithm:       KDFAlgorithmSP800108Counter,
				Hash:            "SHA-512",
				KeyLength:       100,
				Label:           []byte("label"),
				Context:         []byte("context"),
				CounterLength:   16,
				CounterLocation: "middle",
			},
			adapter: kdf.NewSP800108CounterAdapter(),
			expect: &kdf.KDFParams{
				Algorithm:       kdf.AlgorithmSP800108Counter,
				Hash:            crypto.SHA512,
				KeyLength:       100,
				Label:           []byte("label"),
				Context:         []byte("context"),
				CounterLength:   16,
				CounterLocation: "middle",
			},
		},
		{
			name: "SP800-108 feedback with IV",
			params: &KDFParams{
				Algorithm: KDFAlgorithmSP800108Feedback,
				Hash:      "SHA-256",
				KeyLength: 64,
				Label:     []byte("label"),
				Context:   []byte("context"),
				IV:        bytes.Repeat([]byte{0x7f}, 32),
			},
			adapter: kdf.NewSP800108FeedbackAdapter(),
			expect: &kdf.KDFParams{
				Algorithm: kdf.AlgorithmSP800108Feedback,
				Hash:      crypto.SHA256,
				KeyLength: 64,
				Label:     []byte("label"),
				Context:   []byte("context"),
				IV:        bytes.Repeat([]byte{0x7f}, 32),
			},
		},
		{
			name: "X9.63",
			params: &KDFParams{
				Algorithm: KDFAlgorithmX963,
				Hash:      "SHA-256",
				KeyLength: 32,
				Info:      []byte("shared-info"),
			},
			adapter: kdf.NewX963Adapter(),
			expect: &kdf.KDFParams{
				Algorithm: kdf.AlgorithmX963,
				Hash:      crypto.SHA256,
				KeyLength: 32,
				Info:      []byte("shared-info"),
			},
		},
		{
			name: "SP800-56A",
			params: &KDFParams{
				Algorithm: KDFAlgorithmSP80056A,
				Hash:      "SHA3-256",
				KeyLength: 32,
				Info:      []byte("other-info"),
			},
			adapter: kdf.NewSP80056AAdapter(),
			expect: &kdf.KDFParams{
				Algorithm: kdf.AlgorithmSP80056A,
				Hash:      crypto.SHA3_256,
				KeyLength: 32,
				Info:      []byte("other-info"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.params.Derive(secret)
			if err != nil {
				t.Fatalf("Derive: %v", err)
			}
			want, err := tt.adapter.DeriveKey(secret, tt.expect)
			if err != nil {
				t.Fatalf("canonical DeriveKey: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("bridge diverged from the canonical adapter\n got: %x\nwant: %x", got, want)
			}
		})
	}
}

// TestDerive_LabelAndContextReachTheKDF proves the bridge does not drop the
// caller's SP 800-108 inputs.
func TestDerive_LabelAndContextReachTheKDF(t *testing.T) {
	secret := convergenceSecret()

	for _, algorithm := range []KDFAlgorithm{KDFAlgorithmSP800108Counter, KDFAlgorithmSP800108Feedback} {
		t.Run(algorithm.String(), func(t *testing.T) {
			reference, err := convergenceParams(algorithm).Derive(secret)
			if err != nil {
				t.Fatalf("Derive: %v", err)
			}

			changedLabel := convergenceParams(algorithm)
			changedLabel.Label = []byte("different-label")
			key, err := changedLabel.Derive(secret)
			if err != nil {
				t.Fatalf("Derive(label): %v", err)
			}
			if bytes.Equal(key, reference) {
				t.Error("changing Label did not change the derived key")
			}

			changedContext := convergenceParams(algorithm)
			changedContext.Context = []byte("different-context")
			key, err = changedContext.Derive(secret)
			if err != nil {
				t.Fatalf("Derive(context): %v", err)
			}
			if bytes.Equal(key, reference) {
				t.Error("changing Context did not change the derived key")
			}
		})
	}
}

// TestDerive_RejectsInapplicableParameters is the guard against the defect
// class where a backend accepts an option and silently ignores it.
func TestDerive_RejectsInapplicableParameters(t *testing.T) {
	tests := []struct {
		name   string
		params *KDFParams
	}{
		{
			name: "SP800-108 counter with HKDF salt",
			params: &KDFParams{
				Algorithm: KDFAlgorithmSP800108Counter,
				Hash:      "SHA-256",
				KeyLength: 32,
				Salt:      []byte("salt"),
			},
		},
		{
			name: "SP800-108 counter with HKDF info",
			params: &KDFParams{
				Algorithm: KDFAlgorithmSP800108Counter,
				Hash:      "SHA-256",
				KeyLength: 32,
				Info:      []byte("info"),
			},
		},
		{
			name: "SP800-108 counter with a feedback IV",
			params: &KDFParams{
				Algorithm: KDFAlgorithmSP800108Counter,
				Hash:      "SHA-256",
				KeyLength: 32,
				IV:        []byte("iv"),
			},
		},
		{
			name: "HKDF with an SP800-108 label",
			params: &KDFParams{
				Algorithm: KDFAlgorithmHKDF,
				Hash:      "SHA-256",
				KeyLength: 32,
				Label:     []byte("label"),
			},
		},
		{
			name: "HKDF with an SP800-108 context",
			params: &KDFParams{
				Algorithm: KDFAlgorithmHKDF,
				Hash:      "SHA-256",
				KeyLength: 32,
				Context:   []byte("context"),
			},
		},
		{
			name: "HKDF with a counter width",
			params: &KDFParams{
				Algorithm:     KDFAlgorithmHKDF,
				Hash:          "SHA-256",
				KeyLength:     32,
				CounterLength: 32,
			},
		},
		{
			name: "HKDF with a counter location",
			params: &KDFParams{
				Algorithm:       KDFAlgorithmHKDF,
				Hash:            "SHA-256",
				KeyLength:       32,
				CounterLocation: "before",
			},
		},
		{
			name: "X9.63 with a salt",
			params: &KDFParams{
				Algorithm: KDFAlgorithmX963,
				Hash:      "SHA-256",
				KeyLength: 32,
				Salt:      []byte("salt"),
			},
		},
		{
			name: "SP800-56A with a salt",
			params: &KDFParams{
				Algorithm: KDFAlgorithmSP80056A,
				Hash:      "SHA-256",
				KeyLength: 32,
				Salt:      []byte("salt"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.params.Derive(convergenceSecret()); !errors.Is(err, ErrKDFParamNotApplicable) {
				t.Errorf("Derive = %v, want ErrKDFParamNotApplicable", err)
			}
			if err := tt.params.Validate(); !errors.Is(err, ErrKDFParamNotApplicable) {
				t.Errorf("Validate = %v, want ErrKDFParamNotApplicable", err)
			}
		})
	}
}

// TestDerive_RejectsUnsupportedInputs covers the remaining error paths.
func TestDerive_RejectsUnsupportedInputs(t *testing.T) {
	secret := convergenceSecret()

	t.Run("nil receiver", func(t *testing.T) {
		var params *KDFParams
		if _, err := params.Derive(secret); !errors.Is(err, ErrUnsupportedKDFAlgorithm) {
			t.Errorf("got %v, want ErrUnsupportedKDFAlgorithm", err)
		}
	})

	t.Run("unknown algorithm", func(t *testing.T) {
		params := &KDFParams{Algorithm: KDFAlgorithm("SP800-108-TRIPLE"), Hash: "SHA-256", KeyLength: 32}
		if _, err := params.Derive(secret); !errors.Is(err, ErrUnsupportedKDFAlgorithm) {
			t.Errorf("got %v, want ErrUnsupportedKDFAlgorithm", err)
		}
	})

	t.Run("empty algorithm", func(t *testing.T) {
		params := &KDFParams{Hash: "SHA-256", KeyLength: 32}
		if _, err := params.Derive(secret); !errors.Is(err, ErrUnsupportedKDFAlgorithm) {
			t.Errorf("got %v, want ErrUnsupportedKDFAlgorithm", err)
		}
	})

	t.Run("unapproved hashes", func(t *testing.T) {
		// SHA-1, MD5, and friends name real hashes but are not approved KDF
		// pseudorandom functions, so they must not be reachable by name.
		for _, name := range []string{"SHA-1", "MD5", "MD4", "SHA-224", "BLAKE2b-256", "", "sha256"} {
			params := &KDFParams{Algorithm: KDFAlgorithmHKDF, Hash: name, KeyLength: 32}
			if _, err := params.Derive(secret); !errors.Is(err, ErrUnsupportedKDFHash) {
				t.Errorf("hash %q: got %v, want ErrUnsupportedKDFHash", name, err)
			}
		}
	})

	t.Run("invalid key length reaches the adapter", func(t *testing.T) {
		params := &KDFParams{Algorithm: KDFAlgorithmSP800108Counter, Hash: "SHA-256", KeyLength: 0}
		if _, err := params.Derive(secret); !errors.Is(err, kdf.ErrInvalidKeyLength) {
			t.Errorf("got %v, want kdf.ErrInvalidKeyLength", err)
		}
	})

	t.Run("invalid counter width reaches the adapter", func(t *testing.T) {
		params := &KDFParams{
			Algorithm:     KDFAlgorithmSP800108Counter,
			Hash:          "SHA-256",
			KeyLength:     32,
			CounterLength: 12,
		}
		if _, err := params.Derive(secret); !errors.Is(err, kdf.ErrInvalidCounterLength) {
			t.Errorf("got %v, want kdf.ErrInvalidCounterLength", err)
		}
	})

	t.Run("invalid counter location reaches the adapter", func(t *testing.T) {
		params := &KDFParams{
			Algorithm:       KDFAlgorithmSP800108Counter,
			Hash:            "SHA-256",
			KeyLength:       32,
			CounterLocation: "diagonal",
		}
		if _, err := params.Derive(secret); !errors.Is(err, kdf.ErrInvalidCounterLocation) {
			t.Errorf("got %v, want kdf.ErrInvalidCounterLocation", err)
		}
	})

	t.Run("empty shared secret", func(t *testing.T) {
		if _, err := convergenceParams(KDFAlgorithmSP800108Counter).Derive(nil); !errors.Is(err, kdf.ErrInvalidIKM) {
			t.Errorf("got %v, want kdf.ErrInvalidIKM", err)
		}
	})
}

// TestKDFParamsValidate_AcceptsSP800108Fields confirms Validate accepts a
// fully specified SP 800-108 parameter set and still defaults the algorithm
// and hash.
func TestKDFParamsValidate_AcceptsSP800108Fields(t *testing.T) {
	params := &KDFParams{
		Algorithm:       KDFAlgorithmSP800108Feedback,
		Hash:            "SHA-512",
		KeyLength:       64,
		Label:           []byte("label"),
		Context:         []byte("context"),
		CounterLength:   24,
		CounterLocation: "after",
		IV:              bytes.Repeat([]byte{0x01}, 64),
	}
	if err := params.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if _, err := params.Derive(convergenceSecret()); err != nil {
		t.Fatalf("Derive: %v", err)
	}

	defaults := &KDFParams{KeyLength: 32}
	if err := defaults.Validate(); err != nil {
		t.Fatalf("Validate(defaults): %v", err)
	}
	if defaults.Algorithm != KDFAlgorithmHKDF {
		t.Errorf("algorithm defaulted to %s, want HKDF", defaults.Algorithm)
	}
	if defaults.Hash != "SHA-256" {
		t.Errorf("hash defaulted to %s, want SHA-256", defaults.Hash)
	}
}
