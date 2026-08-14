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

package tpm2

import (
	"errors"
	"strings"
	"testing"

	gotpm2 "github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/hardware"
)

// TestTranslate_MapsKnownFailures verifies each storage error and TPM response
// code lands on the pivcert sentinel the interface documents.
func TestTranslate_MapsKnownFailures(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want error
	}{
		{"storage closed", hardware.ErrStorageClosed, pivcert.ErrStorageClosed},
		{"not found", storage.ErrNotFound, pivcert.ErrCertificateNotFound},
		{"certificate too large", hardware.ErrCertificateTooLarge, pivcert.ErrCertificateTooLarge},
		{"capacity exceeded", hardware.ErrCapacityExceeded, pivcert.ErrStorageFull},
		{"NV index unavailable", hardware.ErrNVIndexUnavailable, pivcert.ErrStorageFull},
		{"invalid certificate", hardware.ErrInvalidCertificate, pivcert.ErrInvalidCertificate},
		{"nil TPM", hardware.ErrNilTPM, pivcert.ErrTPMNotAvailable},
		{"hardware unavailable", hardware.ErrHardwareUnavailable, pivcert.ErrTPMNotAvailable},
		{"invalid ID", storage.ErrInvalidID, pivcert.ErrInvalidSlot},
		{"invalid data", storage.ErrInvalidData, pivcert.ErrInvalidCertificate},
		{"NV space", gotpm2.TPMRCNVSpace, pivcert.ErrStorageFull},
		{"NV range", gotpm2.TPMRCNVRange, pivcert.ErrStorageFull},
		{"NV defined", gotpm2.TPMRCNVDefined, pivcert.ErrNVIndexExists},
		{"bad auth", gotpm2.TPMRCBadAuth, pivcert.ErrPermissionDenied},
		{"auth fail", gotpm2.TPMRCAuthFail, pivcert.ErrPermissionDenied},
		{"NV authorization", gotpm2.TPMRCNVAuthorization, pivcert.ErrPermissionDenied},
		{"NV locked", gotpm2.TPMRCNVLocked, pivcert.ErrPermissionDenied},
		{"bad handle", gotpm2.TPMRCHandle, pivcert.ErrCertificateNotFound},
		{"NV unavailable", gotpm2.TPMRCNVUnavailable, pivcert.ErrTPMNotAvailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Wrapped the way the hardware layer reports it.
			wrapped := hardware.NewOperationError("operation", tt.err)

			got := translate(wrapped)
			if !errors.Is(got, tt.want) {
				t.Fatalf("translate(%v) = %v, want %v", tt.err, got, tt.want)
			}
			if !errors.Is(got, tt.err) {
				t.Errorf("translate(%v) dropped the originating failure: %v", tt.err, got)
			}
		})
	}
}

// TestTranslate_UnclassifiedFailures covers errors the table does not name.
func TestTranslate_UnclassifiedFailures(t *testing.T) {
	if got := translate(nil); got != nil {
		t.Errorf("translate(nil) = %v, want nil", got)
	}

	// An error that never reached the TPM carries no response code, so it is
	// reported as an unreachable device rather than as a storage answer.
	transportFailure := hardware.NewOperationError("write", errors.New("input/output error"))
	got := translate(transportFailure)
	if !errors.Is(got, pivcert.ErrTPMNotAvailable) {
		t.Errorf("translate(transport failure) = %v, want ErrTPMNotAvailable", got)
	}
	if !errors.Is(got, transportFailure) {
		t.Errorf("translate(transport failure) dropped the cause: %v", got)
	}

	// An unmapped TPM response code is a genuine answer from the device and is
	// passed through so the caller can read the code.
	unmapped := hardware.NewOperationError("execute", gotpm2.TPMRCInitialize)
	passthrough := translate(unmapped)
	if !errors.Is(passthrough, gotpm2.TPMRCInitialize) {
		t.Errorf("translate(unmapped rc) = %v, want the TPM response code preserved", passthrough)
	}
	if errors.Is(passthrough, pivcert.ErrTPMNotAvailable) {
		t.Error("an answered command was reported as an unreachable TPM")
	}
}

// TestTranslatedError_Behaviour covers the error type's message, unwrapping and
// sentinel matching.
func TestTranslatedError_Behaviour(t *testing.T) {
	cause := hardware.NewOperationError("define NV index", gotpm2.TPMRCNVSpace)
	err := &TranslatedError{Sentinel: pivcert.ErrStorageFull, Cause: cause}

	message := err.Error()
	if !strings.Contains(message, pivcert.ErrStorageFull.Error()) {
		t.Errorf("Error() = %q, want it to name the sentinel", message)
	}
	if !strings.Contains(message, "define NV index") {
		t.Errorf("Error() = %q, want it to name the failing operation", message)
	}

	if !errors.Is(err, pivcert.ErrStorageFull) {
		t.Error("errors.Is(err, ErrStorageFull) = false, want true")
	}
	if !errors.Is(err, gotpm2.TPMRCNVSpace) {
		t.Error("errors.Is(err, TPMRCNVSpace) = false, want true")
	}
	if errors.Is(err, pivcert.ErrCertificateNotFound) {
		t.Error("errors.Is(err, ErrCertificateNotFound) = true, want false")
	}
	if !errors.Is(err.Unwrap(), gotpm2.TPMRCNVSpace) {
		t.Error("Unwrap() lost the TPM response code")
	}
}

// TestStorageError_CarriesSlotContext verifies the wrapped errors the adapter
// returns keep both the slot context and the sentinel.
func TestStorageError_CarriesSlotContext(t *testing.T) {
	err := storageError("Store", pivcert.PIVSlotAuthentication, hardware.ErrNVIndexUnavailable)
	if !errors.Is(err, pivcert.ErrStorageFull) {
		t.Fatalf("storageError() = %v, want ErrStorageFull", err)
	}

	var storageErr *pivcert.PIVStorageError
	if !errors.As(err, &storageErr) {
		t.Fatal("storageError() did not produce a PIVStorageError")
	}
	if storageErr.Slot != pivcert.PIVSlotAuthentication {
		t.Errorf("Slot = %q, want %q", storageErr.Slot, pivcert.PIVSlotAuthentication)
	}
	if storageErr.Op != "Store" {
		t.Errorf("Op = %q, want Store", storageErr.Op)
	}

	typeErr := storageTypeError("List", hardware.ErrStorageClosed)
	if !errors.Is(typeErr, pivcert.ErrStorageClosed) {
		t.Fatalf("storageTypeError() = %v, want ErrStorageClosed", typeErr)
	}
	if !errors.As(typeErr, &storageErr) {
		t.Fatal("storageTypeError() did not produce a PIVStorageError")
	}
	if storageErr.StorageType != pivcert.StorageTypeTPM2 {
		t.Errorf("StorageType = %q, want %q", storageErr.StorageType, pivcert.StorageTypeTPM2)
	}
}
