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

package pkcs11mgr

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrors_Distinct(t *testing.T) {
	t.Parallel()

	allErrors := []error{
		ErrModuleNotFound,
		ErrModuleAlreadyLoaded,
		ErrModuleLoadFailed,
		ErrModuleInitFailed,
		ErrModuleFinalizeFailed,
		ErrSlotNotFound,
		ErrTokenNotPresent,
		ErrSessionOpenFailed,
		ErrSessionCloseFailed,
		ErrLoginFailed,
		ErrInvalidLibraryPath,
		ErrManagerClosed,
	}

	// Verify each error is unique by comparing every pair.
	for i, errA := range allErrors {
		for j, errB := range allErrors {
			if i == j {
				continue
			}
			assert.False(t, errors.Is(errA, errB),
				"errors at index %d and %d should be distinct: %q vs %q",
				i, j, errA.Error(), errB.Error())
		}
	}
}

func TestErrors_NotNil(t *testing.T) {
	t.Parallel()

	allErrors := []error{
		ErrModuleNotFound,
		ErrModuleAlreadyLoaded,
		ErrModuleLoadFailed,
		ErrModuleInitFailed,
		ErrModuleFinalizeFailed,
		ErrSlotNotFound,
		ErrTokenNotPresent,
		ErrSessionOpenFailed,
		ErrSessionCloseFailed,
		ErrLoginFailed,
		ErrInvalidLibraryPath,
		ErrManagerClosed,
	}

	for _, err := range allErrors {
		assert.NotNil(t, err)
		assert.NotEmpty(t, err.Error())
	}
}

func TestErrors_ContainPrefix(t *testing.T) {
	t.Parallel()

	allErrors := []error{
		ErrModuleNotFound,
		ErrModuleAlreadyLoaded,
		ErrModuleLoadFailed,
		ErrModuleInitFailed,
		ErrModuleFinalizeFailed,
		ErrSlotNotFound,
		ErrTokenNotPresent,
		ErrSessionOpenFailed,
		ErrSessionCloseFailed,
		ErrLoginFailed,
		ErrInvalidLibraryPath,
		ErrManagerClosed,
	}

	for _, err := range allErrors {
		assert.Contains(t, err.Error(), "pkcs11mgr:",
			"error should contain package prefix: %q", err.Error())
	}
}

func TestErrors_IsComparison(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
	}{
		{"ModuleNotFound", ErrModuleNotFound},
		{"ModuleAlreadyLoaded", ErrModuleAlreadyLoaded},
		{"ModuleLoadFailed", ErrModuleLoadFailed},
		{"ModuleInitFailed", ErrModuleInitFailed},
		{"ModuleFinalizeFailed", ErrModuleFinalizeFailed},
		{"SlotNotFound", ErrSlotNotFound},
		{"TokenNotPresent", ErrTokenNotPresent},
		{"SessionOpenFailed", ErrSessionOpenFailed},
		{"SessionCloseFailed", ErrSessionCloseFailed},
		{"LoginFailed", ErrLoginFailed},
		{"InvalidLibraryPath", ErrInvalidLibraryPath},
		{"ManagerClosed", ErrManagerClosed},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.True(t, errors.Is(tc.err, tc.err),
				"error should be equal to itself via errors.Is")
		})
	}
}
