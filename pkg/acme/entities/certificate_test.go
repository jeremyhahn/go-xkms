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

package entities

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

func TestACMECertificate_EntityID(t *testing.T) {
	cert := &ACMECertificate{
		Serial: "1a2b3c4d5e6f00112233445566778899",
	}

	id := cert.EntityID()

	// Must match FNV-1a hash of the Serial string.
	expected := StringToEntityID("1a2b3c4d5e6f00112233445566778899")
	assert.Equal(t, expected, id)
	assert.NotZero(t, id)
}

func TestACMECertificate_EntityID_CachedNumericID(t *testing.T) {
	cachedID := uint64(77777)
	cert := &ACMECertificate{
		NumericID: cachedID,
		Serial:    "1a2b3c4d5e6f00112233445566778899",
	}

	id := cert.EntityID()

	// Must return the cached NumericID without recomputing from Serial.
	assert.Equal(t, cachedID, id)
}

func TestACMECertificate_EntityID_EmptySerial(t *testing.T) {
	cert := &ACMECertificate{}

	id := cert.EntityID()

	// Both NumericID and Serial are zero/empty, so EntityID returns 0.
	assert.Zero(t, id)
}

func TestACMECertificate_SetEntityID(t *testing.T) {
	cert := &ACMECertificate{NumericID: 100}
	newID := uint64(200)

	cert.SetEntityID(newID)

	if cert.NumericID != newID {
		t.Errorf("SetEntityID() set NumericID = %v, want %v", cert.NumericID, newID)
	}
	// Subsequent EntityID() calls must return the set value without
	// recomputing from Serial.
	assert.Equal(t, newID, cert.EntityID())
}

func TestACMECertificate_EntityID_CollidingLowBits(t *testing.T) {
	// Two distinct 128-bit serials that share the same low 64 bits must not
	// collide once identity is keyed on the full Serial string. This is the
	// regression this entity shape exists to close (go-xkms#744).
	certA := &ACMECertificate{Serial: "ffeeddccbbaa99880000000000000001"}
	certB := &ACMECertificate{Serial: "11223344556677880000000000000001"}

	assert.NotEqual(t, certA.Serial, certB.Serial)
	// A hash collision across two arbitrary distinct strings is
	// astronomically unlikely with FNV-1a's 64-bit output space, unlike the
	// deterministic collision produced by truncating to low 64 bits.
	assert.NotEqual(t, certA.EntityID(), certB.EntityID())
}

func TestACMECertificate_JSONMarshaling(t *testing.T) {
	issuedAt := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	expiresAt := time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC)

	tests := []struct {
		name    string
		cert    *ACMECertificate
		wantErr bool
	}{
		{
			name: "Valid certificate",
			cert: &ACMECertificate{
				Serial:    "1",
				CertURL:   "https://example.com/acme/cert/1",
				PEM:       "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
				IssuedAt:  issuedAt,
				Status:    "valid",
				ExpiresAt: expiresAt,
			},
			wantErr: false,
		},
		{
			name: "Minimal certificate",
			cert: &ACMECertificate{
				Serial:    "2",
				CertURL:   "https://example.com/acme/cert/2",
				PEM:       "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
				IssuedAt:  issuedAt,
				Status:    "valid",
				ExpiresAt: expiresAt,
			},
			wantErr: false,
		},
		{
			name: "Revoked certificate",
			cert: &ACMECertificate{
				Serial:    "3",
				CertURL:   "https://example.com/acme/cert/3",
				PEM:       "-----BEGIN CERTIFICATE-----\nREVOKED\n-----END CERTIFICATE-----",
				IssuedAt:  issuedAt,
				Status:    "revoked",
				ExpiresAt: expiresAt,
			},
			wantErr: false,
		},
		{
			name: "Full 128-bit serial",
			cert: &ACMECertificate{
				Serial:    "ff00000000000000ee00000000000000",
				CertURL:   "https://example.com/acme/cert/ff00000000000000ee00000000000000",
				PEM:       "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
				IssuedAt:  issuedAt,
				Status:    "valid",
				ExpiresAt: expiresAt,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal to JSON
			jsonData, err := json.Marshal(tt.cert)
			if (err != nil) != tt.wantErr {
				t.Errorf("json.Marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Unmarshal from JSON
			var unmarshaled ACMECertificate
			if err := json.Unmarshal(jsonData, &unmarshaled); err != nil {
				t.Errorf("json.Unmarshal() error = %v", err)
				return
			}

			// Verify key fields
			if unmarshaled.Serial != tt.cert.Serial {
				t.Errorf("Serial mismatch: got %v, want %v", unmarshaled.Serial, tt.cert.Serial)
			}
			if unmarshaled.CertURL != tt.cert.CertURL {
				t.Errorf("CertURL mismatch: got %v, want %v", unmarshaled.CertURL, tt.cert.CertURL)
			}
			if unmarshaled.PEM != tt.cert.PEM {
				t.Errorf("PEM mismatch: got %v, want %v", unmarshaled.PEM, tt.cert.PEM)
			}
			if unmarshaled.Status != tt.cert.Status {
				t.Errorf("Status mismatch: got %v, want %v", unmarshaled.Status, tt.cert.Status)
			}
			if !unmarshaled.IssuedAt.Equal(tt.cert.IssuedAt) {
				t.Errorf("IssuedAt mismatch: got %v, want %v", unmarshaled.IssuedAt, tt.cert.IssuedAt)
			}
			if !unmarshaled.ExpiresAt.Equal(tt.cert.ExpiresAt) {
				t.Errorf("ExpiresAt mismatch: got %v, want %v", unmarshaled.ExpiresAt, tt.cert.ExpiresAt)
			}
		})
	}
}

func TestACMECertificate_YAMLMarshaling(t *testing.T) {
	issuedAt := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	expiresAt := time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC)

	cert := &ACMECertificate{
		Serial:    "1",
		CertURL:   "https://example.com/acme/cert/1",
		PEM:       "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----",
		IssuedAt:  issuedAt,
		Status:    "valid",
		ExpiresAt: expiresAt,
	}

	// Marshal to YAML
	yamlData, err := yaml.Marshal(cert)
	if err != nil {
		t.Fatalf("yaml.Marshal() error = %v", err)
	}

	// Unmarshal from YAML
	var unmarshaled ACMECertificate
	if err := yaml.Unmarshal(yamlData, &unmarshaled); err != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", err)
	}

	// Verify fields
	if unmarshaled.Serial != cert.Serial {
		t.Errorf("Serial mismatch: got %v, want %v", unmarshaled.Serial, cert.Serial)
	}
	if unmarshaled.Status != cert.Status {
		t.Errorf("Status mismatch: got %v, want %v", unmarshaled.Status, cert.Status)
	}
	if unmarshaled.CertURL != cert.CertURL {
		t.Errorf("CertURL mismatch: got %v, want %v", unmarshaled.CertURL, cert.CertURL)
	}
}

func TestACMECertificate_TimeHandling(t *testing.T) {
	now := time.Now()
	future := now.Add(365 * 24 * time.Hour)

	cert := &ACMECertificate{
		Serial:    "1",
		CertURL:   "https://example.com/acme/cert/1",
		PEM:       "test-pem",
		IssuedAt:  now,
		Status:    "valid",
		ExpiresAt: future,
	}

	jsonData, err := json.Marshal(cert)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var unmarshaled ACMECertificate
	if err := json.Unmarshal(jsonData, &unmarshaled); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	// Verify time fields are properly handled
	if !unmarshaled.IssuedAt.Equal(now) {
		t.Errorf("IssuedAt not preserved: got %v, want %v", unmarshaled.IssuedAt, now)
	}

	if !unmarshaled.ExpiresAt.Equal(future) {
		t.Errorf("ExpiresAt not preserved: got %v, want %v", unmarshaled.ExpiresAt, future)
	}

	// Verify certificate is valid
	if unmarshaled.ExpiresAt.Before(unmarshaled.IssuedAt) {
		t.Error("ExpiresAt should be after IssuedAt")
	}
}

func TestACMECertificate_ZeroValues(t *testing.T) {
	cert := &ACMECertificate{}

	if cert.Serial != "" {
		t.Errorf("Expected empty Serial, got %v", cert.Serial)
	}

	if cert.Status != "" {
		t.Errorf("Expected empty status, got %v", cert.Status)
	}

	if !cert.IssuedAt.IsZero() {
		t.Errorf("Expected zero IssuedAt, got %v", cert.IssuedAt)
	}

	if !cert.ExpiresAt.IsZero() {
		t.Errorf("Expected zero ExpiresAt, got %v", cert.ExpiresAt)
	}
}
