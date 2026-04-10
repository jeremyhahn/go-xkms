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

package agent

import (
	"testing"
	"time"
)

func TestAgentEntity_EntityID_RoundTrip(t *testing.T) {
	e := &AgentEntity{}
	e.SetEntityID(55)
	if got := e.EntityID(); got != 55 {
		t.Fatalf("EntityID() = %d, want 55", got)
	}
}

func TestAgentEntity_ZeroValue(t *testing.T) {
	var e AgentEntity
	if got := e.EntityID(); got != 0 {
		t.Fatalf("zero-value EntityID() = %d, want 0", got)
	}
}

func TestAgentEntity_ToAgentInfo(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	e := &AgentEntity{
		ID:              1,
		DeviceID:        "abcdef1234567890",
		Name:            "agent-abcdef12",
		Address:         "192.168.1.100:9443",
		CertFingerprint: "abcdef1234567890abcdef1234567890",
		Status:          "active",
		EnrolledAt:      now,
		LastSeenAt:      now.Add(-10 * time.Minute),
	}

	info := e.ToAgentInfo()

	if info.ID != e.DeviceID {
		t.Errorf("ID = %q, want %q", info.ID, e.DeviceID)
	}
	if info.Name != e.Name {
		t.Errorf("Name = %q, want %q", info.Name, e.Name)
	}
	if info.Address != e.Address {
		t.Errorf("Address = %q, want %q", info.Address, e.Address)
	}
	if info.CertificateFingerprint != e.CertFingerprint {
		t.Errorf("CertificateFingerprint = %q, want %q", info.CertificateFingerprint, e.CertFingerprint)
	}
	if info.Status != e.Status {
		t.Errorf("Status = %q, want %q", info.Status, e.Status)
	}
	if !info.EnrolledAt.Equal(e.EnrolledAt) {
		t.Errorf("EnrolledAt = %v, want %v", info.EnrolledAt, e.EnrolledAt)
	}
	if !info.LastSeen.Equal(e.LastSeenAt) {
		t.Errorf("LastSeen = %v, want %v", info.LastSeen, e.LastSeenAt)
	}
}

func TestAgentEntityFromInfo(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	info := &AgentInfo{
		ID:                     "device-abc",
		Name:                   "test-agent",
		Address:                "10.0.0.1:9443",
		CertificateFingerprint: "fingerprint-hash",
		Status:                 "revoked",
		EnrolledAt:             now,
		LastSeen:               now,
	}

	e := AgentEntityFromInfo(info)

	if e.ID != 0 {
		t.Errorf("new entity ID = %d, want 0", e.ID)
	}
	if e.DeviceID != info.ID {
		t.Errorf("DeviceID = %q, want %q", e.DeviceID, info.ID)
	}
	if e.CertFingerprint != info.CertificateFingerprint {
		t.Errorf("CertFingerprint = %q, want %q", e.CertFingerprint, info.CertificateFingerprint)
	}
	if e.Status != info.Status {
		t.Errorf("Status = %q, want %q", e.Status, info.Status)
	}
}
