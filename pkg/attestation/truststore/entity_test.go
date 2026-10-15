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

package truststore

import (
	"testing"
	"time"
)

func TestTrustCertEntity_EntityID_RoundTrip(t *testing.T) {
	e := &TrustCertEntity{}
	e.SetEntityID(101)
	if got := e.EntityID(); got != 101 {
		t.Fatalf("EntityID() = %d, want 101", got)
	}
}

func TestTrustCertEntity_ZeroValue(t *testing.T) {
	var e TrustCertEntity
	if got := e.EntityID(); got != 0 {
		t.Fatalf("zero-value EntityID() = %d, want 0", got)
	}
}

func TestTrustCertEntityFromMetadata(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	meta := &CertMetadata{
		Subject:     "CN=Test CA",
		Issuer:      "CN=Root CA",
		Fingerprint: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		NotBefore:   now.Add(-365 * 24 * time.Hour),
		NotAfter:    now.Add(365 * 24 * time.Hour),
		Algorithm:   "ECDSA",
		AddedAt:     now,
		Purpose:     PurposeUserCA,
		Source:      "manual",
	}
	pemData := "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"

	e := TrustCertEntityFromMetadata(meta, pemData)

	if e.ID != 0 {
		t.Errorf("new entity ID = %d, want 0", e.ID)
	}
	if e.Fingerprint != meta.Fingerprint {
		t.Errorf("Fingerprint = %q, want %q", e.Fingerprint, meta.Fingerprint)
	}
	if e.Purpose != string(meta.Purpose) {
		t.Errorf("Purpose = %q, want %q", e.Purpose, string(meta.Purpose))
	}
	if e.Subject != meta.Subject {
		t.Errorf("Subject = %q, want %q", e.Subject, meta.Subject)
	}
	if e.Issuer != meta.Issuer {
		t.Errorf("Issuer = %q, want %q", e.Issuer, meta.Issuer)
	}
	if e.Algorithm != meta.Algorithm {
		t.Errorf("Algorithm = %q, want %q", e.Algorithm, meta.Algorithm)
	}
	if !e.NotBefore.Equal(meta.NotBefore) {
		t.Errorf("NotBefore = %v, want %v", e.NotBefore, meta.NotBefore)
	}
	if !e.NotAfter.Equal(meta.NotAfter) {
		t.Errorf("NotAfter = %v, want %v", e.NotAfter, meta.NotAfter)
	}
	if e.PEM != pemData {
		t.Errorf("PEM = %q, want %q", e.PEM, pemData)
	}
	if e.Source != meta.Source {
		t.Errorf("Source = %q, want %q", e.Source, meta.Source)
	}
	if !e.AddedAt.Equal(meta.AddedAt) {
		t.Errorf("AddedAt = %v, want %v", e.AddedAt, meta.AddedAt)
	}
}
