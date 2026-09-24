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

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
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
	if xkms.BackendTypeSoftware != "software" {
		t.Errorf("BackendTypeSoftware = %q, want %q", xkms.BackendTypeSoftware, "software")
	}
	if xkms.BackendTypeTPM2 != "tpm2" {
		t.Errorf("BackendTypeTPM2 = %q, want %q", xkms.BackendTypeTPM2, "tpm2")
	}
	if xkms.BackendTypePKCS11 != "pkcs11" {
		t.Errorf("BackendTypePKCS11 = %q, want %q", xkms.BackendTypePKCS11, "pkcs11")
	}
}

// TestDetailError_ComposesAndUnwraps verifies DetailError's documented
// contract: Error() appends Detail directly after the wrapped error's own
// message, and Unwrap() still exposes the wrapped sentinel to errors.Is.
func TestDetailError_ComposesAndUnwraps(t *testing.T) {
	err := &DetailError{Err: ErrKeyNotFound, Detail: ": credential-abc"}

	if got, want := err.Error(), ErrKeyNotFound.Error()+": credential-abc"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(err, ErrKeyNotFound) {
		t.Error("errors.Is(err, ErrKeyNotFound) = false, want true")
	}
}

// TestMessageError_CarriesItsMessageVerbatim verifies MessageError is a leaf
// error whose Error() returns exactly the preformatted message, with no
// accidental relation to an unrelated sentinel.
func TestMessageError_CarriesItsMessageVerbatim(t *testing.T) {
	err := &MessageError{Msg: "unsupported key type: string"}

	if got, want := err.Error(), "unsupported key type: string"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if errors.Is(err, ErrKeyNotFound) {
		t.Error("errors.Is(err, ErrKeyNotFound) = true, want false (no relation)")
	}
}

// TestSentinelCauseError_MatchesBothSentinelAndCause verifies errors.Is
// matches both the package sentinel and the backend's underlying cause.
func TestSentinelCauseError_MatchesBothSentinelAndCause(t *testing.T) {
	cause := errors.New("provider: connection reset")
	err := &SentinelCauseError{Sentinel: ErrKeyGenerationFailed, Cause: cause}

	if got, want := err.Error(), ErrKeyGenerationFailed.Error()+": "+cause.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(err, ErrKeyGenerationFailed) {
		t.Error("errors.Is(err, ErrKeyGenerationFailed) = false, want true")
	}
	if !errors.Is(err, cause) {
		t.Error("errors.Is(err, cause) = false, want true")
	}
}

// TestWrappedError_ComposesAndUnwraps verifies WrappedError joins Msg and
// the wrapped cause with ": " and exposes the cause to errors.Is.
func TestWrappedError_ComposesAndUnwraps(t *testing.T) {
	cause := errors.New("x509: malformed certificate")
	err := &WrappedError{Msg: "attestation certificate", Err: cause}

	if got, want := err.Error(), "attestation certificate: x509: malformed certificate"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(err, cause) {
		t.Error("errors.Is(err, cause) = false, want true")
	}
}
