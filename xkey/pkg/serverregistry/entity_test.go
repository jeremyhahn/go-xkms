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

package serverregistry

import (
	"testing"
	"time"
)

func TestServerEntity_EntityID_RoundTrip(t *testing.T) {
	e := &ServerEntity{}
	e.SetEntityID(99)
	if got := e.EntityID(); got != 99 {
		t.Fatalf("EntityID() = %d, want 99", got)
	}
}

func TestServerEntity_ZeroValue(t *testing.T) {
	var e ServerEntity
	if got := e.EntityID(); got != 0 {
		t.Fatalf("zero-value EntityID() = %d, want 0", got)
	}
}

func TestServerEntity_ToServerEntry(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	e := &ServerEntity{
		ID:              1,
		URL:             "https://xkms.example.com:8443",
		Name:            "production",
		CAFingerprint:   "abc123def456",
		Protocol:        ProtocolGRPC,
		RegisteredAt:    now,
		LastConnectedAt: now.Add(-5 * time.Minute),
	}

	entry := e.ToServerEntry()

	if entry.URL != e.URL {
		t.Errorf("URL = %q, want %q", entry.URL, e.URL)
	}
	if entry.Name != e.Name {
		t.Errorf("Name = %q, want %q", entry.Name, e.Name)
	}
	if entry.CAFingerprint != e.CAFingerprint {
		t.Errorf("CAFingerprint = %q, want %q", entry.CAFingerprint, e.CAFingerprint)
	}
	if entry.Protocol != e.Protocol {
		t.Errorf("Protocol = %q, want %q", entry.Protocol, e.Protocol)
	}
	if !entry.RegisteredAt.Equal(e.RegisteredAt) {
		t.Errorf("RegisteredAt = %v, want %v", entry.RegisteredAt, e.RegisteredAt)
	}
	if !entry.LastConnectedAt.Equal(e.LastConnectedAt) {
		t.Errorf("LastConnectedAt = %v, want %v", entry.LastConnectedAt, e.LastConnectedAt)
	}
}

func TestServerEntityFromEntry(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	entry := &ServerEntry{
		URL:             "https://xkms.local:8443",
		Name:            "dev",
		CAFingerprint:   "deadbeef",
		Protocol:        ProtocolREST,
		RegisteredAt:    now,
		LastConnectedAt: now,
	}

	e := ServerEntityFromEntry(entry)

	if e.ID != 0 {
		t.Errorf("new entity ID = %d, want 0", e.ID)
	}
	if e.URL != entry.URL {
		t.Errorf("URL = %q, want %q", e.URL, entry.URL)
	}
	if e.Protocol != entry.Protocol {
		t.Errorf("Protocol = %q, want %q", e.Protocol, entry.Protocol)
	}
}
