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
	"github.com/jeremyhahn/go-xkms/pkg/oidc/credential"
	"github.com/jeremyhahn/go-xkms/pkg/scope"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// wireExpectationForClass is this package's half of the cross-transport
// parity check pinned by go-xkms#912; see
// pkg/api/grpc/apierrors_parity_test.go's identically-named type and
// TestClassification_MatchesSharedTables for the gRPC half and the full
// rationale. The two tables encode the SAME semantic outcome per
// apierrors.Class, rendered in each transport's own wire vocabulary:
// JSON-RPC's coarser one collapses ClassFailedPrecondition, ClassDataLoss and
// ClassDeadlineExceeded onto ErrCodeInternalError (there is no dedicated
// code for any of the three), matching the floor pkg/api/mcp's other
// sentinel tables already use for the same gap.
type wireExpectation struct {
	// name is a short, human label for the expectation, used only in
	// sub-test names.
	name string
	// mcpCode is the JSON-RPC code this package's mapImportExportError /
	// mapPIVError / mapBarrierError must produce for a sentinel of this
	// Class.
	mcpCode int
}

var wireExpectationForClass = map[apierrors.Class]wireExpectation{
	apierrors.ClassInternal:           {"internal", ErrCodeInternalError},
	apierrors.ClassInvalidArgument:    {"invalid argument", ErrCodeInvalidParams},
	apierrors.ClassNotFound:           {"not found", sdkssh.JSONRPCCodeNotFound},
	apierrors.ClassAlreadyExists:      {"already exists", sdkssh.JSONRPCCodeDuplicate},
	apierrors.ClassPermissionDenied:   {"permission denied", ErrCodeForbidden},
	apierrors.ClassFailedPrecondition: {"failed precondition", ErrCodeInternalError},
	apierrors.ClassUnavailable:        {"unavailable", ErrCodeServiceUnavailable},
	apierrors.ClassUnimplemented:      {"unimplemented", ErrCodeMethodNotFound},
	apierrors.ClassUnauthenticated:    {"unauthenticated", ErrCodeInvalidParams},
	apierrors.ClassDataLoss:           {"data loss", ErrCodeInternalError},
	apierrors.ClassDeadlineExceeded:   {"deadline exceeded", ErrCodeInternalError},
	apierrors.ClassResourceExhausted:  {"resource exhausted", ErrCodeInternalError},
}

// errParityUpstream stands in for a provider failure under a RefreshError.
var errParityUpstream = errors.New("test: upstream failed")

// TestClassification_MatchesSharedTables walks every sentinel in
// apierrors.ImportExportSentinelClasses, PIVSentinelClasses,
// BarrierSentinelClasses, SealStoreSentinelClasses, PINSentinelClasses,
// CustodianSentinelClasses, TPMPolicySentinelClasses and
// OIDCCredentialSentinelClasses (with the OIDC credential typed errors) and
// asserts this package's mapImportExportError / mapPIVError /
// mapBarrierError / mapSealStoreError / mapPINError / mapCustodianError /
// mapTPMPolicyError / mapOIDCCredentialError renders the JSON-RPC code
// wireExpectationForClass names for that sentinel's Class. It is the MCP
// half of the cross-transport parity pinned by go-xkms#912; see
// pkg/api/grpc/apierrors_parity_test.go for the gRPC half.
func TestClassification_MatchesSharedTables(t *testing.T) {
	t.Run("import/export", func(t *testing.T) {
		for _, entry := range apierrors.ImportExportSentinelClasses {
			want, ok := wireExpectationForClass[entry.Class]
			require.True(t, ok, "no wire expectation for class %v", entry.Class)
			t.Run(want.name, func(t *testing.T) {
				err := mapImportExportError("op", entry.Sentinel)
				var keyErr *KeyOpError
				require.ErrorAs(t, err, &keyErr)
				assert.Equal(t, want.mcpCode, keyErr.Code)
			})
		}
	})

	t.Run("piv", func(t *testing.T) {
		for _, entry := range apierrors.PIVSentinelClasses {
			want, ok := wireExpectationForClass[entry.Class]
			require.True(t, ok, "no wire expectation for class %v", entry.Class)
			t.Run(want.name, func(t *testing.T) {
				err := mapPIVError(entry.Sentinel, "op")
				var keyErr *KeyOpError
				require.ErrorAs(t, err, &keyErr)
				assert.Equal(t, want.mcpCode, keyErr.Code)
			})
		}
	})

	t.Run("barrier", func(t *testing.T) {
		for _, entry := range apierrors.BarrierSentinelClasses {
			want, ok := wireExpectationForClass[entry.Class]
			require.True(t, ok, "no wire expectation for class %v", entry.Class)
			t.Run(want.name, func(t *testing.T) {
				err := mapBarrierError(entry.Sentinel, "op")
				var keyErr *KeyOpError
				require.ErrorAs(t, err, &keyErr)
				assert.Equal(t, want.mcpCode, keyErr.Code)
			})
		}
	})

	t.Run("seal store", func(t *testing.T) {
		for _, entry := range apierrors.SealStoreSentinelClasses {
			want, ok := wireExpectationForClass[entry.Class]
			require.True(t, ok, "no wire expectation for class %v", entry.Class)
			t.Run(want.name, func(t *testing.T) {
				err := mapSealStoreError(entry.Sentinel)
				var keyErr *KeyOpError
				require.ErrorAs(t, err, &keyErr)
				assert.Equal(t, want.mcpCode, keyErr.Code)
			})
		}
	})

	t.Run("pin", func(t *testing.T) {
		for _, entry := range apierrors.PINSentinelClasses {
			want, ok := wireExpectationForClass[entry.Class]
			require.True(t, ok, "no wire expectation for class %v", entry.Class)
			t.Run(want.name, func(t *testing.T) {
				err := mapPINError(entry.Sentinel, "op")
				var keyErr *KeyOpError
				require.ErrorAs(t, err, &keyErr)
				assert.Equal(t, want.mcpCode, keyErr.Code)
			})
		}
	})

	t.Run("custodian", func(t *testing.T) {
		for _, entry := range apierrors.CustodianSentinelClasses {
			want, ok := wireExpectationForClass[entry.Class]
			require.True(t, ok, "no wire expectation for class %v", entry.Class)
			t.Run(want.name, func(t *testing.T) {
				err := mapCustodianError(entry.Sentinel, "op")
				var keyErr *KeyOpError
				require.ErrorAs(t, err, &keyErr)
				assert.Equal(t, want.mcpCode, keyErr.Code)
			})
		}
	})

	t.Run("tpm policy", func(t *testing.T) {
		for _, entry := range apierrors.TPMPolicySentinelClasses {
			want, ok := wireExpectationForClass[entry.Class]
			require.True(t, ok, "no wire expectation for class %v", entry.Class)
			t.Run(want.name, func(t *testing.T) {
				err := mapTPMPolicyError(entry.Sentinel, "op")
				var keyErr *KeyOpError
				require.ErrorAs(t, err, &keyErr)
				assert.Equal(t, want.mcpCode, keyErr.Code)
			})
		}
	})

	t.Run("oidc credential", func(t *testing.T) {
		for _, entry := range apierrors.OIDCCredentialSentinelClasses {
			want, ok := wireExpectationForClass[entry.Class]
			require.True(t, ok, "no wire expectation for class %v", entry.Class)
			t.Run(want.name, func(t *testing.T) {
				err := mapOIDCCredentialError(entry.Sentinel, "op")
				var keyErr *KeyOpError
				require.ErrorAs(t, err, &keyErr)
				assert.Equal(t, want.mcpCode, keyErr.Code)
			})
		}
		typed := map[string]struct {
			err   error
			class apierrors.Class
		}{
			"config":          {&credential.ConfigError{Detail: "d"}, apierrors.ClassInvalidArgument},
			"scope":           {&scope.InvalidScopeError{Value: "galaxy"}, apierrors.ClassInvalidArgument},
			"retryable fault": {&credential.RefreshError{Name: "ci", Err: errParityUpstream}, apierrors.ClassUnavailable},
			"relogin":         {&credential.RefreshError{Name: "ci", Relogin: true, Err: errParityUpstream}, apierrors.ClassFailedPrecondition},
		}
		for name, tc := range typed {
			t.Run(name, func(t *testing.T) {
				err := mapOIDCCredentialError(tc.err, "op")
				var keyErr *KeyOpError
				require.ErrorAs(t, err, &keyErr)
				assert.Equal(t, wireExpectationForClass[tc.class].mcpCode, keyErr.Code)
			})
		}
	})

	// aead has no dedicated mapXError function of its own: its two sentinels
	// are classified inline inside mapKeyOpError (see errors_keyops.go), so
	// this walks apierrors.AEADSentinelClasses against mapKeyOpError directly
	// rather than a per-domain wrapper, exactly as go-xkms#1223 added it.
	t.Run("aead", func(t *testing.T) {
		for _, entry := range apierrors.AEADSentinelClasses {
			want, ok := wireExpectationForClass[entry.Class]
			require.True(t, ok, "no wire expectation for class %v", entry.Class)
			t.Run(want.name, func(t *testing.T) {
				err := mapKeyOpError(entry.Sentinel)
				var keyErr *KeyOpError
				require.ErrorAs(t, err, &keyErr)
				assert.Equal(t, want.mcpCode, keyErr.Code)
			})
		}
	})
}
