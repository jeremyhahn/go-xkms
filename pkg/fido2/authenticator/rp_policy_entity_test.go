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

import (
	"testing"
	"time"
)

func TestRPPolicyEntity_ZeroValue(t *testing.T) {
	var e RPPolicyEntity
	if e.EntityID() != 0 {
		t.Fatalf("expected zero value EntityID to be 0, got %d", e.EntityID())
	}
}

func TestRPPolicyEntity_SetEntityID(t *testing.T) {
	var e RPPolicyEntity

	e.SetEntityID(15)
	if e.EntityID() != 15 {
		t.Fatalf("expected EntityID 15 after SetEntityID, got %d", e.EntityID())
	}

	e.SetEntityID(0)
	if e.EntityID() != 0 {
		t.Fatalf("expected EntityID 0 after reset, got %d", e.EntityID())
	}
}

func TestRPPolicyEntity_FieldPopulation(t *testing.T) {
	now := time.Now()
	upOverride := true
	e := RPPolicyEntity{
		ID:                      1,
		RPID:                    "example.com",
		PolicyName:              "enterprise-default",
		AllowedAlgorithms:       "-7,-257",
		RequireResidentKey:      true,
		RequireUserVerification: true,
		UVOverride:              "required",
		UPOverride:              &upOverride,
		AttestationOverride:     "direct",
		Enterprise:              true,
		Blocked:                 false,
		CreatedAt:               now,
		UpdatedAt:               now,
	}

	if e.EntityID() != 1 {
		t.Fatalf("expected EntityID 1, got %d", e.EntityID())
	}
	if e.RPID != "example.com" {
		t.Fatalf("expected RPID 'example.com', got %q", e.RPID)
	}
	if e.AllowedAlgorithms != "-7,-257" {
		t.Fatalf("expected AllowedAlgorithms '-7,-257', got %q", e.AllowedAlgorithms)
	}
	if e.UPOverride == nil || *e.UPOverride != true {
		t.Fatalf("expected UPOverride to be true, got %v", e.UPOverride)
	}
}
