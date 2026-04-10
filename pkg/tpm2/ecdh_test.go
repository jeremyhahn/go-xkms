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
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestECDHZGen_NilKeyAttributes tests error handling for nil key attributes
func TestECDHZGen_NilKeyAttributes(t *testing.T) {
	tpm := &TPM2{}

	peerPoint := &tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
		Y: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
	}

	_, err := tpm.ECDHZGen(nil, peerPoint, nil)
	if err != store.ErrInvalidKeyAttributes {
		t.Errorf("expected ErrInvalidKeyAttributes, got %v", err)
	}
}

// TestECDHZGen_NilPeerPublicKey tests error handling for nil peer public key
func TestECDHZGen_NilPeerPublicKey(t *testing.T) {
	tpm := &TPM2{}

	keyAttrs := &types.KeyAttributes{
		CN: "test-key",
	}

	_, err := tpm.ECDHZGen(keyAttrs, nil, nil)
	if err != store.ErrInvalidPublicKey {
		t.Errorf("expected ErrInvalidPublicKey, got %v", err)
	}
}

// TestECDHZGen_InterfaceCompliance verifies the method exists on TPM2 type
func TestECDHZGen_InterfaceCompliance(t *testing.T) {
	// This test verifies at compile time that TPM2 implements the ECDHZGen method
	// that's required by the TrustedPlatformModule interface
	var _ TrustedPlatformModule = (*TPM2)(nil)
}
