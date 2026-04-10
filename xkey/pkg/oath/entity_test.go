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

package oath

import (
	"testing"
	"time"
)

func TestOATHCredentialEntity_ZeroValue(t *testing.T) {
	var e OATHCredentialEntity
	if e.EntityID() != 0 {
		t.Fatalf("expected zero value EntityID to be 0, got %d", e.EntityID())
	}
}

func TestOATHCredentialEntity_SetEntityID(t *testing.T) {
	var e OATHCredentialEntity

	e.SetEntityID(42)
	if e.EntityID() != 42 {
		t.Fatalf("expected EntityID 42 after SetEntityID, got %d", e.EntityID())
	}

	e.SetEntityID(0)
	if e.EntityID() != 0 {
		t.Fatalf("expected EntityID 0 after reset, got %d", e.EntityID())
	}
}

func TestOATHCredentialEntity_FieldPopulation(t *testing.T) {
	now := time.Now()
	e := OATHCredentialEntity{
		ID:          1,
		Name:        "GitHub",
		Issuer:      "github.com",
		AccountName: "user@example.com",
		Type:        TypeTOTP,
		Secret:      "JBSWY3DPEHPK3PXP",
		Algorithm:   AlgorithmSHA1,
		Digits:      6,
		Period:      30,
		Counter:     0,
		BackendID:   "software",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if e.EntityID() != 1 {
		t.Fatalf("expected EntityID 1, got %d", e.EntityID())
	}
	if e.Name != "GitHub" {
		t.Fatalf("expected Name 'GitHub', got %q", e.Name)
	}
	if e.Type != TypeTOTP {
		t.Fatalf("expected Type %q, got %q", TypeTOTP, e.Type)
	}
}
