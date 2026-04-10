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

package services

import (
	"testing"
	"time"
)

func TestSealedBlobEntity_EntityID_RoundTrip(t *testing.T) {
	e := &SealedBlobEntity{
		Label:      "backup-key",
		BackendID:  "tpm2-default",
		PolicyType: "platform_policy",
		SealedData: []byte{0xDE, 0xAD},
	}

	const wantID uint64 = 77
	e.SetEntityID(wantID)

	if got := e.EntityID(); got != wantID {
		t.Errorf("EntityID() = %d, want %d", got, wantID)
	}
}

func TestSealedBlobEntity_ZeroValue(t *testing.T) {
	var e SealedBlobEntity

	if got := e.EntityID(); got != 0 {
		t.Errorf("zero-value EntityID() = %d, want 0", got)
	}
}

func TestSealedBlobEntity_SetEntityID_Overwrite(t *testing.T) {
	e := &SealedBlobEntity{}
	e.SetEntityID(10)
	e.SetEntityID(300)

	if got := e.EntityID(); got != 300 {
		t.Errorf("EntityID() after overwrite = %d, want 300", got)
	}
}

func TestSealedBlobEntity_FieldsPreserved(t *testing.T) {
	now := time.Now().UTC()
	data := []byte("encrypted-payload-bytes")
	e := &SealedBlobEntity{
		Label:       "secret-blob",
		BackendID:   "software",
		PolicyType:  "password",
		PolicyName:  "my-policy",
		StorageType: "disk",
		Category:    "credentials",
		SizeBytes:   len(data),
		PCRBound:    true,
		SealedData:  data,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	e.SetEntityID(15)

	if e.EntityID() != 15 {
		t.Fatal("EntityID mismatch")
	}
	if e.Label != "secret-blob" {
		t.Error("Label not preserved")
	}
	if e.BackendID != "software" {
		t.Error("BackendID not preserved")
	}
	if !e.PCRBound {
		t.Error("PCRBound not preserved")
	}
	if len(e.SealedData) != len(data) {
		t.Errorf("SealedData len = %d, want %d", len(e.SealedData), len(data))
	}
}
