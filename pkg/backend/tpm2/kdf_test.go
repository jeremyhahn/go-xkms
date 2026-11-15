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

package tpm2

import (
	"context"
	"crypto"
	"errors"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/kdf"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// newMockTPMBackend builds a Backend over the package's mockTPM, which
// implements TrustedPlatformModule but cannot unseal anything. It is the right
// fixture for the wiring and refusal paths; the derivation itself needs a real
// TPM and is covered by kdf_sim_test.go under the tpm_simulator build tag.
func newMockTPMBackend(t *testing.T) *Backend {
	t.Helper()

	b, err := NewBackendWithTPM(&ExternalTPMConfig{
		TPM:        &mockTPM{ssrkAttrsValue: &types.KeyAttributes{CN: "test-ssrk"}},
		KeyBackend: &mockKeyBackend{},
		Logger:     slog.Default(),
		Tracker:    backend.NewMemoryAEADTracker(),
	})
	if err != nil {
		t.Fatalf("NewBackendWithTPM: %v", err)
	}
	return b
}

func tpmKDFParams() *kdf.KDFParams {
	return &kdf.KDFParams{
		Algorithm: kdf.AlgorithmHKDF,
		Hash:      crypto.SHA256,
		Salt:      []byte("salt"),
		Info:      []byte("info"),
		KeyLength: 32,
	}
}

// TestDeriveFromSymmetricKey_TPMWithoutUnsealCapability proves the refusal is
// truthful.
//
// symmetricDeriver is asserted at the point of use rather than added to
// pkgtpm2.TrustedPlatformModule, so a TrustedPlatformModule that cannot unseal
// — every test double in the stack — is reported as a backend that cannot
// derive, not silently derived from something else.
func TestDeriveFromSymmetricKey_TPMWithoutUnsealCapability(t *testing.T) {
	b := newMockTPMBackend(t)

	derived, err := b.DeriveFromSymmetricKey(context.Background(), &types.KeyAttributes{
		CN:                 "sealed-key",
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}, tpmKDFParams())

	if !errors.Is(err, types.ErrKeyDerivationNotSupported) {
		t.Fatalf("got %v, want types.ErrKeyDerivationNotSupported", err)
	}
	if len(derived) != 0 {
		t.Fatalf("a refused derivation returned %d bytes of key material", len(derived))
	}
}

// TestDeriveFromSymmetricKey_RejectsBadInput covers the refusals that do not
// depend on the TPM.
func TestDeriveFromSymmetricKey_RejectsBadInput(t *testing.T) {
	b := newMockTPMBackend(t)
	ctx := context.Background()

	t.Run("nil attributes", func(t *testing.T) {
		if _, err := b.DeriveFromSymmetricKey(ctx, nil, tpmKDFParams()); !errors.Is(err, ErrInvalidKeyAttributes) {
			t.Fatalf("got %v, want ErrInvalidKeyAttributes", err)
		}
	})

	t.Run("nil parameters", func(t *testing.T) {
		attrs := &types.KeyAttributes{CN: "sealed-key", SymmetricAlgorithm: types.SymmetricAES256GCM}
		if _, err := b.DeriveFromSymmetricKey(ctx, attrs, nil); !errors.Is(err, types.ErrUnsupportedKDFAlgorithm) {
			t.Fatalf("got %v, want types.ErrUnsupportedKDFAlgorithm", err)
		}
	})

	t.Run("closed backend", func(t *testing.T) {
		closed := newMockTPMBackend(t)
		if err := closed.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		attrs := &types.KeyAttributes{CN: "sealed-key", SymmetricAlgorithm: types.SymmetricAES256GCM}
		if _, err := closed.DeriveFromSymmetricKey(ctx, attrs, tpmKDFParams()); !errors.Is(err, ErrNotInitialized) {
			t.Fatalf("got %v, want ErrNotInitialized", err)
		}
	})
}
