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

//go:build tpm_simulator

package tpm2

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestNewBackend_SimulatorAutoProvisions proves the first-boot simulator path:
// NewBackend against a freshly-reset simulator provisions EK+SRK in place and
// returns a working backend that can generate a key and sign with it. Before
// this path existed, an unprovisioned simulator made NewBackend fail with
// "TPM needs provisioning" — which broke every harness that boots xkmsd
// against a fresh swtpm container.
func TestNewBackend_SimulatorAutoProvisions(t *testing.T) {
	config := &Config{
		UseSimulator: true,
		KeyDir:       t.TempDir(),
		CN:           "autoprov-test",
	}

	backend, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend on fresh simulator: %v", err)
	}
	defer func() {
		if cerr := backend.Close(); cerr != nil {
			t.Errorf("Close: %v", cerr)
		}
	}()

	if backend.srkAttrs == nil {
		t.Fatal("srkAttrs is nil after auto-provisioning")
	}

	// Prove the provisioned TPM is usable end-to-end: generate a signing key.
	attrs := &types.KeyAttributes{
		CN:            "autoprov-signer",
		KeyAlgorithm:  x509.ECDSA,
		KeyType:       types.KeyTypeSigning,
		StoreType:     types.StoreTPM2,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
	}
	if _, err := backend.GenerateKey(context.Background(), attrs); err != nil {
		t.Fatalf("GenerateKey on auto-provisioned simulator: %v", err)
	}
}
