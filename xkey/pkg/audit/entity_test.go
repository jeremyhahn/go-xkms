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

package audit

import (
	"testing"
	"time"
)

func TestAuditEntryEntity_ZeroValue(t *testing.T) {
	var e AuditEntryEntity
	if e.EntityID() != 0 {
		t.Fatalf("expected zero value EntityID to be 0, got %d", e.EntityID())
	}
}

func TestAuditEntryEntity_SetEntityID(t *testing.T) {
	var e AuditEntryEntity

	e.SetEntityID(99)
	if e.EntityID() != 99 {
		t.Fatalf("expected EntityID 99 after SetEntityID, got %d", e.EntityID())
	}

	e.SetEntityID(0)
	if e.EntityID() != 0 {
		t.Fatalf("expected EntityID 0 after reset, got %d", e.EntityID())
	}
}

func TestAuditEntryEntity_FieldPopulation(t *testing.T) {
	now := time.Now()
	e := AuditEntryEntity{
		ID:         1,
		Timestamp:  now,
		Operation:  OpKeyCreated,
		Backend:    "software",
		KeyID:      "key-123",
		DeviceID:   "dev-456",
		DeviceName: "Test Device",
		Success:    true,
		Error:      "",
		DurationMs: 42,
		Details:    map[string]any{"algo": "ES256"},
	}

	if e.EntityID() != 1 {
		t.Fatalf("expected EntityID 1, got %d", e.EntityID())
	}
	if e.Operation != OpKeyCreated {
		t.Fatalf("expected Operation %q, got %q", OpKeyCreated, e.Operation)
	}
	if e.Details["algo"] != "ES256" {
		t.Fatalf("expected Details[algo] = 'ES256', got %v", e.Details["algo"])
	}
}
