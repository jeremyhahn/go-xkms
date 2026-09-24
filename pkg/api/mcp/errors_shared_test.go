// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package mcp

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/apierrors"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// TestMapImportExportError_DomainSentinels asserts the JSON-RPC code for
// every sentinel in apierrors.ImportExportSentinelClasses -- the table
// go-xkms#912 made this package share with pkg/api/grpc's
// mapImportExportError.
func TestMapImportExportError_DomainSentinels(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code int
	}{
		{"export not supported", backend.ErrExportNotSupported, ErrCodeMethodNotFound},
		{"import not supported", backend.ErrImportNotSupported, ErrCodeMethodNotFound},
		{"asymmetric export not allowed", backend.ErrAsymmetricKeyExportNotAllowed, ErrCodeInvalidParams},
		{"key not exportable", backend.ErrKeyNotExportable, ErrCodeForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mapImportExportError("failed to wrap key", tt.err)
			var keyErr *KeyOpError
			require.ErrorAs(t, err, &keyErr)
			assert.Equal(t, tt.code, keyErr.Code)
			assert.ErrorIs(t, err, tt.err)
		})
	}
}

// TestMapImportExportError_Unclassified proves mapImportExportError's floor:
// an error absent from apierrors.ImportExportSentinelClasses still becomes a
// classified *KeyOpError (ErrCodeInternalError) rather than an unwrapped
// error the dispatcher cannot recognise.
func TestMapImportExportError_Unclassified(t *testing.T) {
	err := mapImportExportError("failed to wrap key", errors.New("hsm exploded"))
	var keyErr *KeyOpError
	require.ErrorAs(t, err, &keyErr)
	assert.Equal(t, ErrCodeInternalError, keyErr.Code)
}

// TestMapImportExportError_Nil proves mapImportExportError passes a nil
// error through unchanged.
func TestMapImportExportError_Nil(t *testing.T) {
	assert.NoError(t, mapImportExportError("failed to wrap key", nil))
}

// TestMapPIVError_DomainSentinels asserts the JSON-RPC code for every
// sentinel in apierrors.PIVSentinelClasses -- the table go-xkms#912 made
// this package share with pkg/api/grpc's mapPIVError.
func TestMapPIVError_DomainSentinels(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code int
	}{
		{"not initialized", xkms.ErrPIVNotInitialized, ErrCodeInternalError},
		{"backend not found", xkms.ErrPIVBackendNotFound, sdkssh.JSONRPCCodeNotFound},
		{"invalid algorithm", xkms.ErrPIVInvalidAlgorithm, ErrCodeInvalidParams},
		{"invalid slot", xkms.ErrPIVInvalidSlot, ErrCodeInvalidParams},
		{"invalid format", xkms.ErrPIVInvalidFormat, ErrCodeInvalidParams},
		{"key not found", xkms.ErrPIVKeyNotFound, sdkssh.JSONRPCCodeNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mapPIVError(tt.err, "failed to list PIV slots")
			var keyErr *KeyOpError
			require.ErrorAs(t, err, &keyErr)
			assert.Equal(t, tt.code, keyErr.Code)
			assert.ErrorIs(t, err, tt.err)
		})
	}
}

// TestMapPIVError_Unclassified proves mapPIVError's floor for a PIV error
// outside apierrors.PIVSentinelClasses.
func TestMapPIVError_Unclassified(t *testing.T) {
	err := mapPIVError(errors.New("card removed"), "failed to list PIV slots")
	var keyErr *KeyOpError
	require.ErrorAs(t, err, &keyErr)
	assert.Equal(t, ErrCodeInternalError, keyErr.Code)
}

// TestMapPIVError_Nil proves mapPIVError passes a nil error through
// unchanged.
func TestMapPIVError_Nil(t *testing.T) {
	assert.NoError(t, mapPIVError(nil, "failed to list PIV slots"))
}

// TestMapBarrierError_DomainSentinels asserts the JSON-RPC code for a
// representative sample of apierrors.BarrierSentinelClasses -- the table
// go-xkms#912 made this package share with
// pkg/api/grpc/service_barrier_pin.go's mapBarrierError -- covering each
// Class that table produces.
func TestMapBarrierError_DomainSentinels(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code int
	}{
		{"sealed", seal.ErrSealed, ErrCodeInternalError},                                      // ClassFailedPrecondition
		{"already unsealed", seal.ErrAlreadyUnsealed, sdkssh.JSONRPCCodeDuplicate},            // ClassAlreadyExists
		{"invalid credentials", seal.ErrInvalidCredentials, ErrCodeInvalidParams},             // ClassUnauthenticated
		{"no available strategy", seal.ErrNoAvailableStrategy, ErrCodeServiceUnavailable},     // ClassUnavailable
		{"strategy not found", seal.ErrStrategyNotFound, sdkssh.JSONRPCCodeNotFound},          // ClassNotFound
		{"corrupt root key", seal.ErrCorruptRootKey, ErrCodeInternalError},                    // ClassDataLoss
		{"shamir threshold invalid", seal.ErrShamirThresholdInvalid, ErrCodeInvalidParams},    // ClassInvalidArgument
		{"shamir quorum expired", seal.ErrShamirQuorumExpired, ErrCodeInternalError},          // ClassDeadlineExceeded
		{"shamir combine failed", seal.ErrShamirCombineFailed, ErrCodeInternalError},          // ClassInternal
		{"recovery keys not found", seal.ErrRecoveryKeysNotFound, sdkssh.JSONRPCCodeNotFound}, // ClassNotFound
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mapBarrierError(tt.err, "barrier operation")
			var keyErr *KeyOpError
			require.ErrorAs(t, err, &keyErr)
			assert.Equal(t, tt.code, keyErr.Code)
			assert.ErrorIs(t, err, tt.err)
		})
	}
}

// TestMapBarrierError_Unclassified proves mapBarrierError's floor for a
// barrier error outside apierrors.BarrierSentinelClasses.
func TestMapBarrierError_Unclassified(t *testing.T) {
	err := mapBarrierError(errors.New("disk full"), "barrier operation")
	var keyErr *KeyOpError
	require.ErrorAs(t, err, &keyErr)
	assert.Equal(t, ErrCodeInternalError, keyErr.Code)
}

// TestMapBarrierError_Nil proves mapBarrierError passes a nil error through
// unchanged.
func TestMapBarrierError_Nil(t *testing.T) {
	assert.NoError(t, mapBarrierError(nil, "barrier operation"))
}

// TestJSONRPCCodeForClass_TotalOverSharedTables proves classToJSONRPCCode
// (via jsonRPCCodeForClass) has an entry for every Class the three shared
// apierrors tables can produce, so none of them silently falls through to
// the ErrCodeInternalError floor for a Class that was meant to render more
// precisely.
func TestJSONRPCCodeForClass_TotalOverSharedTables(t *testing.T) {
	tables := [][]apierrors.SentinelClass{
		apierrors.ImportExportSentinelClasses,
		apierrors.PIVSentinelClasses,
		apierrors.BarrierSentinelClasses,
	}
	for _, table := range tables {
		for _, entry := range table {
			_, ok := classToJSONRPCCode[entry.Class]
			assert.True(t, ok, "classToJSONRPCCode has no entry for %v (sentinel %v)", entry.Class, entry.Sentinel)
		}
	}
}
