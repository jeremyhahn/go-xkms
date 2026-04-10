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

package keybackend

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func TestErrors_KeyNotFound(t *testing.T) {
	err := ErrKeyNotFound
	if err == nil {
		t.Error("ErrKeyNotFound should not be nil")
	}
	if err.Error() != "keybackend: key not found" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func TestErrors_UnsupportedAlgorithm(t *testing.T) {
	err := ErrUnsupportedAlgorithm
	if err == nil {
		t.Error("ErrUnsupportedAlgorithm should not be nil")
	}
	if err.Error() != "keybackend: unsupported algorithm" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func TestErrors_ExportNotSupported(t *testing.T) {
	err := ErrExportNotSupported
	if err == nil {
		t.Error("ErrExportNotSupported should not be nil")
	}
	if err.Error() != "keybackend: export not supported" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func TestErrors_ImportNotSupported(t *testing.T) {
	err := ErrImportNotSupported
	if err == nil {
		t.Error("ErrImportNotSupported should not be nil")
	}
	if err.Error() != "keybackend: import not supported" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func TestErrors_InvalidKeyHandle(t *testing.T) {
	err := ErrInvalidKeyHandle
	if err == nil {
		t.Error("ErrInvalidKeyHandle should not be nil")
	}
	if err.Error() != "keybackend: invalid key handle" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func TestErrors_KeyGenerationFailed(t *testing.T) {
	err := ErrKeyGenerationFailed
	if err == nil {
		t.Error("ErrKeyGenerationFailed should not be nil")
	}
	if err.Error() != "keybackend: key generation failed" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func TestErrors_SigningFailed(t *testing.T) {
	err := ErrSigningFailed
	if err == nil {
		t.Error("ErrSigningFailed should not be nil")
	}
	if err.Error() != "keybackend: signing failed" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func TestErrors_AttestationNotSupported(t *testing.T) {
	err := ErrAttestationNotSupported
	if err == nil {
		t.Error("ErrAttestationNotSupported should not be nil")
	}
	if err.Error() != "keybackend: attestation not supported" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func TestErrors_BackendClosed(t *testing.T) {
	err := ErrBackendClosed
	if err == nil {
		t.Error("ErrBackendClosed should not be nil")
	}
	if err.Error() != "keybackend: backend closed" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func TestErrors_InvalidCredentialID(t *testing.T) {
	err := ErrInvalidCredentialID
	if err == nil {
		t.Error("ErrInvalidCredentialID should not be nil")
	}
	if err.Error() != "keybackend: invalid credential ID" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func TestErrors_InvalidPKCS8Key(t *testing.T) {
	err := ErrInvalidPKCS8Key
	if err == nil {
		t.Error("ErrInvalidPKCS8Key should not be nil")
	}
	if err.Error() != "keybackend: invalid PKCS#8 key" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func TestErrors_IsChecks(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		target error
		want   bool
	}{
		{"KeyNotFound matches", ErrKeyNotFound, ErrKeyNotFound, true},
		{"UnsupportedAlgorithm matches", ErrUnsupportedAlgorithm, ErrUnsupportedAlgorithm, true},
		{"ExportNotSupported matches", ErrExportNotSupported, ErrExportNotSupported, true},
		{"different errors don't match", ErrKeyNotFound, ErrUnsupportedAlgorithm, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := errors.Is(tt.err, tt.target); got != tt.want {
				t.Errorf("errors.Is(%v, %v) = %v, want %v", tt.err, tt.target, got, tt.want)
			}
		})
	}
}

func TestBackendType_Constants(t *testing.T) {
	if types.BackendTypeSoftware != "software" {
		t.Errorf("BackendTypeSoftware = %q, want %q", types.BackendTypeSoftware, "software")
	}
	if types.BackendTypeTPM2 != "tpm2" {
		t.Errorf("BackendTypeTPM2 = %q, want %q", types.BackendTypeTPM2, "tpm2")
	}
	if types.BackendTypePKCS11 != "pkcs11" {
		t.Errorf("BackendTypePKCS11 = %q, want %q", types.BackendTypePKCS11, "pkcs11")
	}
}
