// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
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

	"gopkg.in/yaml.v3"
)

func TestACMECertificate_EntityID(t *testing.T) {
	tests := []struct {
		name     string
		id       uint64
		expected uint64
	}{
		{
			name:     "Zero ID",
			id:       0,
			expected: 0,
		},
		{
			name:     "Positive ID",
			id:       777,
			expected: 777,
		},
		{
			name:     "Max uint64",
			id:       18446744073709551615,
			expected: 18446744073709551615,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &ACMECertificate{}
			cert.SetEntityID(tt.id)

			if got := cert.EntityID(); got != tt.expected {
				t.Errorf("EntityID() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestACMECertificate_SetEntityID(t *testing.T) {
	cert := &ACMECertificate{ID: 100}
	newID := uint64(200)

	cert.SetEntityID(newID)

	if cert.ID != newID {
		t.Errorf("SetEntityID() set ID = %v, want %v", cert.ID, newID)
	}
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
				ID:        1,
				CertURL:   "https://example.com/cert/1",
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
				ID:        2,
				CertURL:   "https://example.com/cert/2",
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
				ID:        3,
				CertURL:   "https://example.com/cert/3",
				PEM:       "-----BEGIN CERTIFICATE-----\nREVOKED\n-----END CERTIFICATE-----",
				IssuedAt:  issuedAt,
				Status:    "revoked",
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
			if unmarshaled.ID != tt.cert.ID {
				t.Errorf("ID mismatch: got %v, want %v", unmarshaled.ID, tt.cert.ID)
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
		ID:        1,
		CertURL:   "https://example.com/cert/1",
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
	if unmarshaled.ID != cert.ID {
		t.Errorf("ID mismatch: got %v, want %v", unmarshaled.ID, cert.ID)
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
		ID:        1,
		CertURL:   "https://example.com/cert/1",
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

	if cert.ID != 0 {
		t.Errorf("Expected zero ID, got %v", cert.ID)
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
