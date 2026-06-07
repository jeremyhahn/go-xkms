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

package ca

import (
	"errors"
	"math/big"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// TestRevocationPersistence_SurvivesReload is the durability guard: a revocation
// recorded against a datastore-backed CA is restored by a fresh CA over the same
// store (modeling a process restart). Before this fix the revocations map was
// in-memory only, so revoked certificates silently un-revoked on restart.
func TestRevocationPersistence_SurvivesReload(t *testing.T) {
	backend := storage.NewMemory()
	serial := big.NewInt(424242)

	ca1 := &CA{revocationStore: backend, revocations: make(map[string]*RevocationInfo)}
	if err := ca1.recordRevocation(serial, 1, false); err != nil {
		t.Fatalf("recordRevocation: %v", err)
	}

	// A fresh CA over the same backend models a restart.
	ca2 := &CA{revocationStore: backend, revocations: make(map[string]*RevocationInfo)}
	if err := ca2.loadPersistedRevocations(); err != nil {
		t.Fatalf("loadPersistedRevocations: %v", err)
	}
	info, ok := ca2.revocations[serial.Text(10)]
	if !ok {
		t.Fatalf("revocation did not survive reload; map = %v", ca2.revocations)
	}
	if info.Reason != 1 || info.SerialNumber.Cmp(serial) != 0 {
		t.Fatalf("reloaded revocation = %+v, want serial %s reason 1", info, serial)
	}
}

// TestRevocationPersistence_NoStoreInMemoryOnly verifies that without a store the
// revocation is still tracked in memory (Revoke does not fail) but nothing is
// persisted.
func TestRevocationPersistence_NoStoreInMemoryOnly(t *testing.T) {
	ca := &CA{revocations: make(map[string]*RevocationInfo)}
	if err := ca.recordRevocation(big.NewInt(7), 0, false); err != nil {
		t.Fatalf("recordRevocation without store: %v", err)
	}
	if _, ok := ca.revocations["7"]; !ok {
		t.Fatal("expected in-memory revocation to be tracked")
	}
	blobs, err := ca.listRevocationBlobs()
	if err != nil {
		t.Fatalf("listRevocationBlobs: %v", err)
	}
	if len(blobs) != 0 {
		t.Fatalf("expected no persisted blobs without a store, got %d", len(blobs))
	}
}

// TestRevocationPersistence_AlreadyRevoked verifies the duplicate-revocation
// guard holds with a backing store.
func TestRevocationPersistence_AlreadyRevoked(t *testing.T) {
	ca := &CA{revocationStore: storage.NewMemory(), revocations: make(map[string]*RevocationInfo)}
	if err := ca.recordRevocation(big.NewInt(1), 0, false); err != nil {
		t.Fatalf("first recordRevocation: %v", err)
	}
	if err := ca.recordRevocation(big.NewInt(1), 0, false); !errors.Is(err, ErrAlreadyRevoked) {
		t.Fatalf("second recordRevocation = %v, want ErrAlreadyRevoked", err)
	}
}
