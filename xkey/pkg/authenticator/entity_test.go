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

package authenticator

import "testing"

func TestFIDO2CredentialEntity_ZeroValue(t *testing.T) {
	var e FIDO2CredentialEntity
	if e.EntityID() != 0 {
		t.Fatalf("expected zero value EntityID to be 0, got %d", e.EntityID())
	}
}

func TestFIDO2CredentialEntity_SetEntityID(t *testing.T) {
	var e FIDO2CredentialEntity

	e.SetEntityID(7)
	if e.EntityID() != 7 {
		t.Fatalf("expected EntityID 7 after SetEntityID, got %d", e.EntityID())
	}

	e.SetEntityID(0)
	if e.EntityID() != 0 {
		t.Fatalf("expected EntityID 0 after reset, got %d", e.EntityID())
	}
}

func TestFIDO2CredentialEntity_FieldPopulation(t *testing.T) {
	e := FIDO2CredentialEntity{
		ID:              1,
		CredentialIDHex: "deadbeef",
		RPID:            "example.com",
		RPName:          "Example",
		UserIDHex:       "cafebabe",
		UserName:        "alice",
		UserDisplayName: "Alice Smith",
		Algorithm:       -7,
		SignCount:       5,
		CreatedAt:       1700000000,
		Discoverable:    true,
		CredProtect:     2,
		BackendID:       "tpm2",
	}

	if e.EntityID() != 1 {
		t.Fatalf("expected EntityID 1, got %d", e.EntityID())
	}
	if e.RPID != "example.com" {
		t.Fatalf("expected RPID 'example.com', got %q", e.RPID)
	}
	if e.Algorithm != -7 {
		t.Fatalf("expected Algorithm -7, got %d", e.Algorithm)
	}
}
