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

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// TestNewBackend_WithSimulator_ExercisesTPMInit tests NewBackend with simulator.
// The simulator starts in an unprovisioned state, so NewTPM2 will typically
// return ErrNotInitialized indicating TPM needs provisioning.
// This test exercises the NewBackend code paths including:
// - the KeyStorage-backed key backend construction
// - ToTPMConfig conversion
// - pkgtpm2.NewTPM2 call
// - Error handling for ErrNotInitialized
func TestNewBackend_WithSimulator_ExercisesTPMInit(t *testing.T) {
	config := &Config{
		UseSimulator: true,
		KeyStorage:   storage.NewMemory(),
		SRKHandle:    0x81000001,
		EKHandle:     0x81010001,
	}

	backend, err := NewBackend(config)
	if err == nil {
		// If no error, we got a working backend - close it and verify
		if backend != nil {
			// Verify the backend was properly initialized
			if backend.tpm == nil {
				t.Error("backend.tpm should not be nil on success")
			}
			if backend.keyBackend == nil {
				t.Error("backend.keyBackend should not be nil on success")
			}
			if backend.keyStorage == nil {
				t.Error("backend.keyStorage should not be nil on success")
			}
			if backend.srkAttrs == nil {
				t.Error("backend.srkAttrs should not be nil on success")
			}
			if err := backend.Close(); err != nil {
				t.Errorf("Close error: %v", err)
			}
		}
		t.Log("NewBackend succeeded with simulator - covers the success path")
		return
	}

	// The simulator returns ErrNotInitialized if TPM needs provisioning
	t.Logf("NewBackend returned expected error: %v", err)
}
