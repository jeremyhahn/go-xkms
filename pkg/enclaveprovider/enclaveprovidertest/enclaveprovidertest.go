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

// Package enclaveprovidertest proves enclaveprovider over one go-xkms
// backend. A backend's tests build the backend the way they already do in
// memory (a mock KMS client, the TPM simulator, SoftHSM) and make one Run
// call; it runs go-enclave's providertest conformance suite in both modes and
// a sealer round trip through go-enclave itself.
package enclaveprovidertest

import (
	"bytes"
	"errors"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-enclave/providertest"

	"github.com/jeremyhahn/go-xkms/pkg/enclaveprovider"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Backend is the sealer under test and the key it seals under.
type Backend struct {
	// Sealer is the backend.
	Sealer types.Sealer

	// KeyAttributes names the sealing key, which must already exist.
	KeyAttributes *types.KeyAttributes

	// SkipResidueSweep, when non-empty, is why the process-memory residue
	// sweep cannot hold for this backend: an in-process device or mock that
	// keeps its own copy of the plaintext beyond the provider's reach. It is
	// passed to providertest.Config.SkipResidueSweep and logged.
	SkipResidueSweep string
}

// Run proves the KeyProtector and RootUnsealer over b.
func Run(t *testing.T, b Backend) {
	t.Helper()

	t.Run("KeyProtector conformance", func(t *testing.T) {
		err := providertest.TestProvider(t.Context(), providertest.Config{
			New: func() (any, error) {
				return enclaveprovider.NewKeyProtector(b.Sealer, b.KeyAttributes)
			},
			Modes:            []enclave.Mode{enclave.ModePerOperation},
			SkipResidueSweep: b.SkipResidueSweep,
			Logf:             t.Logf,
		})
		if err != nil {
			t.Fatal(err)
		}
	})

	sealedRoot, err := enclaveprovider.ProvisionRoot(t.Context(), b.Sealer, b.KeyAttributes)
	if err != nil {
		t.Fatalf("ProvisionRoot: %v", err)
	}

	t.Run("RootUnsealer conformance", func(t *testing.T) {
		err := providertest.TestProvider(t.Context(), providertest.Config{
			New: func() (any, error) {
				return enclaveprovider.NewRootUnsealer(b.Sealer, b.KeyAttributes, sealedRoot)
			},
			Modes: []enclave.Mode{enclave.ModeRootKey},
			Logf:  t.Logf,
		})
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("enclave sealer round trip", func(t *testing.T) {
		protector, err := enclaveprovider.NewKeyProtector(b.Sealer, b.KeyAttributes)
		if err != nil {
			t.Fatalf("NewKeyProtector: %v", err)
		}
		unsealer, err := enclaveprovider.NewRootUnsealer(b.Sealer, b.KeyAttributes, sealedRoot)
		if err != nil {
			t.Fatalf("NewRootUnsealer: %v", err)
		}
		roundTrip(t, enclave.WithKeyProtector(protector))
		roundTrip(t, enclave.WithRootUnsealer(unsealer))
	})

	t.Run("a blob made for the other seam is refused", func(t *testing.T) {
		protector, err := enclaveprovider.NewKeyProtector(b.Sealer, b.KeyAttributes)
		if err != nil {
			t.Fatalf("NewKeyProtector: %v", err)
		}
		dst := make([]byte, enclave.RootKeyBytes)
		err = protector.Unprotect(t.Context(), sealedRoot, dst)
		if !errors.Is(err, enclave.ErrSealedAuthentication) {
			t.Fatalf("Unprotect(sealed root) = %v, want enclave.ErrSealedAuthentication", err)
		}
		if !bytes.Equal(dst, make([]byte, enclave.RootKeyBytes)) {
			t.Fatal("a refused Unprotect wrote into its destination")
		}

		key := bytes.Repeat([]byte{0x5a}, enclave.RootKeyBytes)
		blob, err := protector.Protect(t.Context(), key)
		if err != nil {
			t.Fatalf("Protect: %v", err)
		}
		_, err = enclaveprovider.NewRootUnsealer(b.Sealer, b.KeyAttributes, blob)
		if !errors.Is(err, enclave.ErrSealedAuthentication) {
			t.Fatalf("NewRootUnsealer(protected key) = %v, want enclave.ErrSealedAuthentication", err)
		}
	})
}

// roundTrip seals material through a go-enclave Sealer built with option and
// opens it again.
func roundTrip(t *testing.T, option enclave.SealerOption) {
	t.Helper()
	sealer, err := enclave.NewSealer(option)
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	t.Cleanup(func() {
		if err := sealer.Destroy(); err != nil {
			t.Errorf("Sealer.Destroy: %v", err)
		}
	})

	want := []byte("material sealed under a go-xkms backend")
	sealed, err := sealer.Seal(t.Context(), bytes.Clone(want))
	if err != nil {
		t.Fatalf("%s Seal: %v", sealer.Mode(), err)
	}
	opened, err := sealed.Open(t.Context())
	if err != nil {
		t.Fatalf("%s Open: %v", sealer.Mode(), err)
	}
	t.Cleanup(func() {
		if err := opened.Destroy(); err != nil {
			t.Errorf("MemoryEnclave.Destroy: %v", err)
		}
	})
	equal, err := opened.EqualTo(want)
	if err != nil {
		t.Fatalf("EqualTo: %v", err)
	}
	if !equal {
		t.Fatalf("%s round trip recovered different material", sealer.Mode())
	}
}
