// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"errors"
	"runtime"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/kdf"
)

// hugeRequestedKeyLength is the go-xkms#1259 report's own example: a caller
// asking a KDF for roughly 100 GB of output in one request. It must be
// refused before any adapter runs a single hash invocation, and refusing it
// must not itself allocate anything proportional to the request.
const hugeRequestedKeyLength = 100_000_000_000

// noBigAllocationBudget is the ceiling this package's own bookkeeping (error
// structs, formatted messages) may allocate while refusing an oversized
// KeyLength. It is generous relative to that bookkeeping and minuscule
// relative to hugeRequestedKeyLength, so a regression that lets the request
// reach an adapter's preallocation trips it by many orders of magnitude
// rather than marginally.
const noBigAllocationBudget = 64 * 1024

// assertNoBigAllocation runs fn and fails the test if it allocated more than
// noBigAllocationBudget bytes, proving a refusal happened before any
// adapter-sized preallocation rather than after one.
func assertNoBigAllocation(t *testing.T, fn func()) {
	t.Helper()

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)

	// TotalAlloc is cumulative and monotonically increasing, so it is immune
	// to a GC that runs between the two snapshots -- unlike HeapAlloc, which
	// a concurrent GC could shrink and produce a false pass.
	delta := after.TotalAlloc - before.TotalAlloc
	if delta > noBigAllocationBudget {
		t.Errorf("refusing an oversized key length allocated %d bytes, want at most %d; "+
			"the cap is being checked after an adapter has already started preallocating output",
			delta, noBigAllocationBudget)
	}
}

// bridgeDeriveParams returns a fully populated, otherwise-valid KDFParams for
// algorithm, missing only KeyLength, which each test case fills in. Every
// field a bridge does not consume is left zero so checkApplicability never
// rejects these for the wrong reason.
func bridgeDeriveParams(algorithm KDFAlgorithm) *KDFParams {
	switch algorithm {
	case KDFAlgorithmHKDF:
		return &KDFParams{Algorithm: algorithm, Hash: "SHA-256", Salt: []byte("salt"), Info: []byte("info")}
	case KDFAlgorithmX963, KDFAlgorithmSP80056A:
		return &KDFParams{Algorithm: algorithm, Hash: "SHA-256", Info: []byte("shared info")}
	case KDFAlgorithmSP800108Counter, KDFAlgorithmSP800108Feedback:
		return &KDFParams{Algorithm: algorithm, Hash: "SHA-256", Label: []byte("label"), Context: []byte("context")}
	case KDFAlgorithmRaw:
		return &KDFParams{Algorithm: algorithm}
	default:
		panic("bridgeDeriveParams: unhandled algorithm " + algorithm.String())
	}
}

// TestKDFParamsDerive_MaxDerivedKeyLength proves KDFParams.Derive enforces
// MaxDerivedKeyLength identically for every algorithm it dispatches to,
// including the raw (CKD_NULL) pass-through at deriveRaw -- the two paths
// go-xkms#1259 named explicitly, because deriveRaw's own bound (KeyLength
// must not exceed the shared secret) does not by itself refuse a KeyLength
// that is merely large, only one that is larger than whatever secret this
// particular call happened to pass.
func TestKDFParamsDerive_MaxDerivedKeyLength(t *testing.T) {
	algorithms := []KDFAlgorithm{
		KDFAlgorithmHKDF,
		KDFAlgorithmX963,
		KDFAlgorithmSP80056A,
		KDFAlgorithmSP800108Counter,
		KDFAlgorithmSP800108Feedback,
		KDFAlgorithmRaw,
	}

	for _, algorithm := range algorithms {
		t.Run(algorithm.String(), func(t *testing.T) {
			// The raw pass-through's own length bound is the shared secret's
			// length, so proving MaxDerivedKeyLength succeeds for it needs a
			// secret at least that long. The bridge algorithms only need
			// enough input keying material to be non-empty.
			secret := bytes.Repeat([]byte{0x42}, MaxDerivedKeyLength)

			t.Run("max length succeeds", func(t *testing.T) {
				params := bridgeDeriveParams(algorithm)
				params.KeyLength = MaxDerivedKeyLength
				derived, err := params.Derive(secret)
				if err != nil {
					t.Fatalf("KeyLength == MaxDerivedKeyLength: got error %v, want success", err)
				}
				if len(derived) != MaxDerivedKeyLength {
					t.Fatalf("got %d derived bytes, want %d", len(derived), MaxDerivedKeyLength)
				}
			})

			t.Run("max length plus one is refused", func(t *testing.T) {
				params := bridgeDeriveParams(algorithm)
				params.KeyLength = MaxDerivedKeyLength + 1
				_, err := params.Derive(secret)
				if !errors.Is(err, ErrKeyLengthTooLarge) {
					t.Fatalf("KeyLength == MaxDerivedKeyLength+1: got %v, want ErrKeyLengthTooLarge", err)
				}
			})

			t.Run("huge length is refused without a large allocation", func(t *testing.T) {
				params := bridgeDeriveParams(algorithm)
				params.KeyLength = hugeRequestedKeyLength

				var err error
				assertNoBigAllocation(t, func() {
					_, err = params.Derive(secret)
				})
				if !errors.Is(err, ErrKeyLengthTooLarge) {
					t.Fatalf("KeyLength == %d: got %v, want ErrKeyLengthTooLarge", hugeRequestedKeyLength, err)
				}
			})
		})
	}
}

// TestKDFParamsValidate_MaxDerivedKeyLength proves Validate enforces the same
// ceiling as Derive for every algorithm, including the RAW branch: Validate
// resolves RAW before reaching the bridge table and used to apply no upper
// bound there at all (go-xkms#1259), which let a RAW DeriveKeyECDH request
// past every backend's kdfParams.Validate() call with an unbounded
// KeyLength.
func TestKDFParamsValidate_MaxDerivedKeyLength(t *testing.T) {
	algorithms := []KDFAlgorithm{
		KDFAlgorithmHKDF,
		KDFAlgorithmX963,
		KDFAlgorithmSP80056A,
		KDFAlgorithmSP800108Counter,
		KDFAlgorithmSP800108Feedback,
		KDFAlgorithmRaw,
	}

	for _, algorithm := range algorithms {
		t.Run(algorithm.String(), func(t *testing.T) {
			t.Run("max length is valid", func(t *testing.T) {
				params := bridgeDeriveParams(algorithm)
				params.KeyLength = MaxDerivedKeyLength
				if err := params.Validate(); err != nil {
					t.Fatalf("KeyLength == MaxDerivedKeyLength: got error %v, want success", err)
				}
			})

			t.Run("max length plus one is refused", func(t *testing.T) {
				params := bridgeDeriveParams(algorithm)
				params.KeyLength = MaxDerivedKeyLength + 1
				err := params.Validate()
				if !errors.Is(err, ErrKeyLengthTooLarge) {
					t.Fatalf("KeyLength == MaxDerivedKeyLength+1: got %v, want ErrKeyLengthTooLarge", err)
				}
			})

			t.Run("huge length is refused", func(t *testing.T) {
				params := bridgeDeriveParams(algorithm)
				params.KeyLength = hugeRequestedKeyLength

				var err error
				assertNoBigAllocation(t, func() {
					err = params.Validate()
				})
				if !errors.Is(err, ErrKeyLengthTooLarge) {
					t.Fatalf("KeyLength == %d: got %v, want ErrKeyLengthTooLarge", hugeRequestedKeyLength, err)
				}
			})
		})
	}
}

// lowLevelDeriveParams mirrors bridgeDeriveParams for the pkg/crypto/kdf
// KDFParams type DeriveFromKeyMaterial takes directly. It exists because
// DeriveFromKeyMaterial is the choke point for DeriveKey's raw-material and
// stored-symmetric-key paths, reached through pkg/crypto/kdf's own
// KDFAlgorithm names rather than the wire-level types.KDFAlgorithm; RAW has
// no equivalent there (kdf.NewAdapter implements no CKD_NULL pass-through),
// matching that DeriveKey never advertises RAW as a supported algorithm.
func lowLevelDeriveParams(algorithm kdf.KDFAlgorithm) *kdf.KDFParams {
	switch algorithm {
	case kdf.AlgorithmHKDF:
		return &kdf.KDFParams{Algorithm: algorithm, Hash: crypto.SHA256, Salt: []byte("salt"), Info: []byte("info")}
	case kdf.AlgorithmX963, kdf.AlgorithmSP80056A:
		return &kdf.KDFParams{Algorithm: algorithm, Hash: crypto.SHA256, Info: []byte("shared info")}
	case kdf.AlgorithmSP800108Counter, kdf.AlgorithmSP800108Feedback, kdf.AlgorithmSP800108DoublePipeline:
		return &kdf.KDFParams{Algorithm: algorithm, Hash: crypto.SHA256, Label: []byte("label"), Context: []byte("context")}
	default:
		panic("lowLevelDeriveParams: unhandled algorithm " + algorithm.String())
	}
}

// TestDeriveFromKeyMaterial_MaxDerivedKeyLength proves DeriveFromKeyMaterial
// enforces MaxDerivedKeyLength before calling kdf.NewAdapter(...).DeriveKey.
// This is the choke point KDFParams.Derive does not cover: DeriveKey's
// raw-input-key-material path and every backend's SymmetricKeyDeriver
// implementation call this function directly with a pkg/crypto/kdf
// KDFParams, never types.KDFParams.Derive (go-xkms#1259).
func TestDeriveFromKeyMaterial_MaxDerivedKeyLength(t *testing.T) {
	algorithms := []kdf.KDFAlgorithm{
		kdf.AlgorithmHKDF,
		kdf.AlgorithmX963,
		kdf.AlgorithmSP80056A,
		kdf.AlgorithmSP800108Counter,
		kdf.AlgorithmSP800108Feedback,
		kdf.AlgorithmSP800108DoublePipeline,
	}
	ikm := bytes.Repeat([]byte{0x24}, 32)

	for _, algorithm := range algorithms {
		t.Run(algorithm.String(), func(t *testing.T) {
			t.Run("max length succeeds", func(t *testing.T) {
				params := lowLevelDeriveParams(algorithm)
				params.KeyLength = MaxDerivedKeyLength
				derived, err := DeriveFromKeyMaterial(ikm, params)
				if err != nil {
					t.Fatalf("KeyLength == MaxDerivedKeyLength: got error %v, want success", err)
				}
				if len(derived) != MaxDerivedKeyLength {
					t.Fatalf("got %d derived bytes, want %d", len(derived), MaxDerivedKeyLength)
				}
			})

			t.Run("max length plus one is refused", func(t *testing.T) {
				params := lowLevelDeriveParams(algorithm)
				params.KeyLength = MaxDerivedKeyLength + 1
				_, err := DeriveFromKeyMaterial(ikm, params)
				if !errors.Is(err, ErrKeyLengthTooLarge) {
					t.Fatalf("KeyLength == MaxDerivedKeyLength+1: got %v, want ErrKeyLengthTooLarge", err)
				}
			})

			t.Run("huge length is refused without a large allocation", func(t *testing.T) {
				params := lowLevelDeriveParams(algorithm)
				params.KeyLength = hugeRequestedKeyLength

				var err error
				assertNoBigAllocation(t, func() {
					_, err = DeriveFromKeyMaterial(ikm, params)
				})
				if !errors.Is(err, ErrKeyLengthTooLarge) {
					t.Fatalf("KeyLength == %d: got %v, want ErrKeyLengthTooLarge", hugeRequestedKeyLength, err)
				}
			})
		})
	}
}
