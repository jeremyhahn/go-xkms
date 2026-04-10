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

package staticpw

import (
	"testing"
	"time"
)

func TestTeamEntity_EntityID_RoundTrip(t *testing.T) {
	e := &TeamEntity{
		Name:     "engineering",
		TenantID: "tenant-1",
		OwnerID:  "owner-1",
		Members:  []string{"alice", "bob"},
	}

	const wantID uint64 = 100
	e.SetEntityID(wantID)

	if got := e.EntityID(); got != wantID {
		t.Errorf("EntityID() = %d, want %d", got, wantID)
	}
}

func TestTeamEntity_ZeroValue(t *testing.T) {
	var e TeamEntity

	if got := e.EntityID(); got != 0 {
		t.Errorf("zero-value EntityID() = %d, want 0", got)
	}
}

func TestTeamEntity_SetEntityID_Overwrite(t *testing.T) {
	e := &TeamEntity{}
	e.SetEntityID(5)
	e.SetEntityID(200)

	if got := e.EntityID(); got != 200 {
		t.Errorf("EntityID() after overwrite = %d, want 200", got)
	}
}

func TestTeamEntity_FieldsPreserved(t *testing.T) {
	now := time.Now().UTC()
	e := &TeamEntity{
		Name:      "devops",
		TenantID:  "tenant-2",
		OwnerID:   "admin-1",
		Members:   []string{"charlie", "dave", "eve"},
		CreatedAt: now,
		UpdatedAt: now,
	}
	e.SetEntityID(50)

	if e.EntityID() != 50 {
		t.Fatal("EntityID mismatch")
	}
	if e.Name != "devops" {
		t.Error("Name not preserved")
	}
	if len(e.Members) != 3 {
		t.Errorf("Members len = %d, want 3", len(e.Members))
	}
	if e.TenantID != "tenant-2" {
		t.Error("TenantID not preserved")
	}
}
