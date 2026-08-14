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

	gotpm2 "github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/hardware"
)

// TranslatedError reports a pivcert sentinel for a failure that came back from
// the TPM storage layer, while keeping the original error reachable.
//
// errors.Is matches both the pivcert sentinel the caller programs against and
// the underlying TPM response code, so diagnostics survive translation.
type TranslatedError struct {
	// Sentinel is the pivcert error the failure maps onto.
	Sentinel error

	// Cause is the hardware or TPM error that produced it.
	Cause error
}

// Error returns the sentinel followed by the originating failure.
func (e *TranslatedError) Error() string {
	return e.Sentinel.Error() + ": " + e.Cause.Error()
}

// Unwrap returns the originating failure so the TPM response code stays
// reachable through errors.Is and errors.As.
func (e *TranslatedError) Unwrap() error {
	return e.Cause
}

// Is reports whether the error maps onto the given pivcert sentinel.
func (e *TranslatedError) Is(target error) bool {
	return errors.Is(e.Sentinel, target)
}

// sentinelMappings translates storage-layer errors and TPM response codes into
// the pivcert sentinels the PIVCertificateStorage contract documents. The order
// is significant: the first match wins, so the specific storage sentinels are
// checked before the broader TPM response codes.
var sentinelMappings = []struct {
	from error
	to   error
}{
	// Storage-layer sentinels.
	{hardware.ErrStorageClosed, pivcert.ErrStorageClosed},
	{storage.ErrNotFound, pivcert.ErrCertificateNotFound},
	{hardware.ErrCertificateTooLarge, pivcert.ErrCertificateTooLarge},
	{hardware.ErrCapacityExceeded, pivcert.ErrStorageFull},
	// The NV index the slot hashes to holds a record belonging to something
	// else, so this slot has nowhere left to live.
	{hardware.ErrNVIndexUnavailable, pivcert.ErrStorageFull},
	{hardware.ErrInvalidCertificate, pivcert.ErrInvalidCertificate},
	{hardware.ErrNilTPM, pivcert.ErrTPMNotAvailable},
	{hardware.ErrHardwareUnavailable, pivcert.ErrTPMNotAvailable},
	{storage.ErrInvalidID, pivcert.ErrInvalidSlot},
	{storage.ErrInvalidData, pivcert.ErrInvalidCertificate},

	// TPM response codes.
	{gotpm2.TPMRCNVSpace, pivcert.ErrStorageFull},
	{gotpm2.TPMRCNVRange, pivcert.ErrStorageFull},
	{gotpm2.TPMRCNVDefined, pivcert.ErrNVIndexExists},
	{gotpm2.TPMRCBadAuth, pivcert.ErrPermissionDenied},
	{gotpm2.TPMRCAuthFail, pivcert.ErrPermissionDenied},
	{gotpm2.TPMRCNVAuthorization, pivcert.ErrPermissionDenied},
	{gotpm2.TPMRCNVLocked, pivcert.ErrPermissionDenied},
	{gotpm2.TPMRCHandle, pivcert.ErrCertificateNotFound},
	{gotpm2.TPMRCNVUnavailable, pivcert.ErrTPMNotAvailable},
}

// translate maps a hardware storage error onto the pivcert sentinel that
// describes it.
//
// An error carrying no TPM response code at all never came back from the TPM:
// the command did not reach the device. Those are reported as
// pivcert.ErrTPMNotAvailable rather than being mistaken for a storage answer.
func translate(err error) error {
	if err == nil {
		return nil
	}

	for _, mapping := range sentinelMappings {
		if errors.Is(err, mapping.from) {
			return &TranslatedError{Sentinel: mapping.to, Cause: err}
		}
	}

	var rc gotpm2.TPMRC
	if !errors.As(err, &rc) {
		return &TranslatedError{Sentinel: pivcert.ErrTPMNotAvailable, Cause: err}
	}

	return err
}

// storageError wraps a translated hardware error with slot and operation
// context, keeping the pivcert sentinel reachable through errors.Is.
func storageError(op string, slot pivcert.PIVSlot, err error) error {
	return pivcert.NewStorageError(op, slot, translate(err))
}

// storageTypeError wraps a translated hardware error with operation context for
// calls that are not scoped to a single slot.
func storageTypeError(op string, err error) error {
	return pivcert.NewStorageTypeError(op, pivcert.StorageTypeTPM2, translate(err))
}
