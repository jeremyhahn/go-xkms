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

func TestPasswordEntity_EntityID_RoundTrip(t *testing.T) {
	e := &PasswordEntity{
		Name:     "test-entry",
		Password: "secret",
	}

	const wantID uint64 = 42
	e.SetEntityID(wantID)

	if got := e.EntityID(); got != wantID {
		t.Errorf("EntityID() = %d, want %d", got, wantID)
	}
}

func TestPasswordEntity_ZeroValue(t *testing.T) {
	var e PasswordEntity

	if got := e.EntityID(); got != 0 {
		t.Errorf("zero-value EntityID() = %d, want 0", got)
	}
}

func TestPasswordEntity_SetEntityID_Overwrite(t *testing.T) {
	e := &PasswordEntity{}
	e.SetEntityID(1)
	e.SetEntityID(99)

	if got := e.EntityID(); got != 99 {
		t.Errorf("EntityID() after overwrite = %d, want 99", got)
	}
}

func TestPasswordEntity_FieldsPreserved(t *testing.T) {
	now := time.Now().UTC()
	e := &PasswordEntity{
		Name:          "my-password",
		Title:         "My Password",
		Username:      "user@example.com",
		Password:      "hunter2",
		URL:           "https://example.com",
		FolderPath:    "Work/Email",
		CreatedAt:     now,
		UpdatedAt:     now,
		OwnerID:       "owner-1",
		TenantID:      "tenant-1",
		Shared:        true,
		MatchPatterns: []string{"*.example.com"},
		Notes:         "important",
	}
	e.SetEntityID(7)

	if e.EntityID() != 7 {
		t.Fatal("EntityID mismatch")
	}
	if e.Name != "my-password" {
		t.Error("Name not preserved")
	}
	if e.TenantID != "tenant-1" {
		t.Error("TenantID not preserved")
	}
	if !e.Shared {
		t.Error("Shared not preserved")
	}
	if len(e.MatchPatterns) != 1 || e.MatchPatterns[0] != "*.example.com" {
		t.Error("MatchPatterns not preserved")
	}
}
