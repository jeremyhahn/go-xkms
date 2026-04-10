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

package pcrpolicy

import (
	"testing"
	"time"
)

func TestPCRPolicyEntity_EntityID_RoundTrip(t *testing.T) {
	e := &PCRPolicyEntity{
		Name: "boot-policy",
		Bank: "SHA256",
		PCRs: map[uint][]byte{
			0: {0x01, 0x02, 0x03},
			7: {0xAA, 0xBB, 0xCC},
		},
		AutoUnseal: true,
	}

	const wantID uint64 = 55
	e.SetEntityID(wantID)

	if got := e.EntityID(); got != wantID {
		t.Errorf("EntityID() = %d, want %d", got, wantID)
	}
}

func TestPCRPolicyEntity_ZeroValue(t *testing.T) {
	var e PCRPolicyEntity

	if got := e.EntityID(); got != 0 {
		t.Errorf("zero-value EntityID() = %d, want 0", got)
	}
}

func TestPCRPolicyEntity_SetEntityID_Overwrite(t *testing.T) {
	e := &PCRPolicyEntity{}
	e.SetEntityID(3)
	e.SetEntityID(88)

	if got := e.EntityID(); got != 88 {
		t.Errorf("EntityID() after overwrite = %d, want 88", got)
	}
}

func TestPCRPolicyEntity_FieldsPreserved(t *testing.T) {
	now := time.Now().UTC()
	pcrs := map[uint][]byte{
		0:  make([]byte, 32),
		7:  make([]byte, 32),
		14: make([]byte, 32),
	}
	e := &PCRPolicyEntity{
		Name:       "secure-boot",
		Bank:       "SHA384",
		PCRs:       pcrs,
		AutoUnseal: false,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	e.SetEntityID(12)

	if e.EntityID() != 12 {
		t.Fatal("EntityID mismatch")
	}
	if e.Name != "secure-boot" {
		t.Error("Name not preserved")
	}
	if e.Bank != "SHA384" {
		t.Error("Bank not preserved")
	}
	if len(e.PCRs) != 3 {
		t.Errorf("PCRs len = %d, want 3", len(e.PCRs))
	}
	if e.AutoUnseal {
		t.Error("AutoUnseal should be false")
	}
}
