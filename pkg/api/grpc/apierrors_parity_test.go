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

package grpc

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-xkms/pkg/api/apierrors"
)

// wireExpectationForClass is the single expected wire-level outcome per
// apierrors.Class, written down once here and mirrored verbatim (as the MCP
// vocabulary permits) in pkg/api/mcp/apierrors_parity_test.go's
// wireExpectationForClass. TestClassification_MatchesMCP in that file and
// TestClassification_MatchesGRPC in this one each check their own
// package's real classification function against this SAME semantic
// per-Class expectation, so a change to either package's Class -> wire-code
// map that drifts from the other's intended outcome fails one of the two
// tests (go-xkms#912): neither test can see the other package's unexported
// map, so this shared semantic anchor is what makes the comparison possible
// at all.
type wireExpectation struct {
	// name is a short, human label for the expectation, used only in
	// sub-test names.
	name string
	// grpcCode is the codes.Code this package's mapImportExportError /
	// mapPIVError / mapBarrierError must produce for a sentinel of this
	// Class.
	grpcCode codes.Code
}

var wireExpectationForClass = map[apierrors.Class]wireExpectation{
	apierrors.ClassInternal:           {"internal", codes.Internal},
	apierrors.ClassInvalidArgument:    {"invalid argument", codes.InvalidArgument},
	apierrors.ClassNotFound:           {"not found", codes.NotFound},
	apierrors.ClassAlreadyExists:      {"already exists", codes.AlreadyExists},
	apierrors.ClassPermissionDenied:   {"permission denied", codes.PermissionDenied},
	apierrors.ClassFailedPrecondition: {"failed precondition", codes.FailedPrecondition},
	apierrors.ClassUnavailable:        {"unavailable", codes.Unavailable},
	apierrors.ClassUnimplemented:      {"unimplemented", codes.Unimplemented},
	apierrors.ClassUnauthenticated:    {"unauthenticated", codes.Unauthenticated},
	apierrors.ClassDataLoss:           {"data loss", codes.DataLoss},
	apierrors.ClassDeadlineExceeded:   {"deadline exceeded", codes.DeadlineExceeded},
	apierrors.ClassResourceExhausted:  {"resource exhausted", codes.ResourceExhausted},
}

// TestClassification_MatchesSharedTables walks every sentinel in
// apierrors.ImportExportSentinelClasses, PIVSentinelClasses,
// BarrierSentinelClasses, SealStoreSentinelClasses, PINSentinelClasses,
// CustodianSentinelClasses and PolicySentinelClasses and asserts this
// package's mapImportExportError / mapPIVError / mapBarrierError /
// mapSealStoreError / mapPINError / mapCustodianError / mapPolicyError
// renders the gRPC status code wireExpectationForClass names for that
// sentinel's Class. It is the gRPC half of the cross-transport parity
// pinned by go-xkms#912; see this file's wireExpectationForClass doc
// comment and pkg/api/mcp/apierrors_parity_test.go's
// TestClassification_MatchesSharedTables for the MCP half.
func TestClassification_MatchesSharedTables(t *testing.T) {
	t.Run("import/export", func(t *testing.T) {
		for _, entry := range apierrors.ImportExportSentinelClasses {
			want, ok := wireExpectationForClass[entry.Class]
			require.True(t, ok, "no wire expectation for class %v", entry.Class)
			t.Run(want.name, func(t *testing.T) {
				err := mapImportExportError("op", entry.Sentinel)
				assert.Equal(t, want.grpcCode, status.Code(err))
			})
		}
	})

	t.Run("piv", func(t *testing.T) {
		for _, entry := range apierrors.PIVSentinelClasses {
			want, ok := wireExpectationForClass[entry.Class]
			require.True(t, ok, "no wire expectation for class %v", entry.Class)
			t.Run(want.name, func(t *testing.T) {
				err := mapPIVError(entry.Sentinel, "op")
				assert.Equal(t, want.grpcCode, status.Code(err))
			})
		}
	})

	t.Run("barrier", func(t *testing.T) {
		for _, entry := range apierrors.BarrierSentinelClasses {
			want, ok := wireExpectationForClass[entry.Class]
			require.True(t, ok, "no wire expectation for class %v", entry.Class)
			t.Run(want.name, func(t *testing.T) {
				err := mapBarrierError(entry.Sentinel, "op")
				assert.Equal(t, want.grpcCode, status.Code(err))
			})
		}
	})

	t.Run("seal store", func(t *testing.T) {
		for _, entry := range apierrors.SealStoreSentinelClasses {
			want, ok := wireExpectationForClass[entry.Class]
			require.True(t, ok, "no wire expectation for class %v", entry.Class)
			t.Run(want.name, func(t *testing.T) {
				err := mapSealStoreError(entry.Sentinel)
				assert.Equal(t, want.grpcCode, status.Code(err))
			})
		}
	})

	t.Run("pin", func(t *testing.T) {
		for _, entry := range apierrors.PINSentinelClasses {
			want, ok := wireExpectationForClass[entry.Class]
			require.True(t, ok, "no wire expectation for class %v", entry.Class)
			t.Run(want.name, func(t *testing.T) {
				err := mapPINError(entry.Sentinel, "op")
				assert.Equal(t, want.grpcCode, status.Code(err))
			})
		}
	})

	t.Run("custodian", func(t *testing.T) {
		for _, entry := range apierrors.CustodianSentinelClasses {
			want, ok := wireExpectationForClass[entry.Class]
			require.True(t, ok, "no wire expectation for class %v", entry.Class)
			t.Run(want.name, func(t *testing.T) {
				err := mapCustodianError(entry.Sentinel, "op")
				assert.Equal(t, want.grpcCode, status.Code(err))
			})
		}
	})

	t.Run("policy", func(t *testing.T) {
		for _, entry := range apierrors.PolicySentinelClasses {
			want, ok := wireExpectationForClass[entry.Class]
			require.True(t, ok, "no wire expectation for class %v", entry.Class)
			t.Run(want.name, func(t *testing.T) {
				err := mapPolicyError(entry.Sentinel)
				assert.Equal(t, want.grpcCode, status.Code(err))
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
				err := mapKeyOpError(context.Background(), nil, entry.Sentinel)
				assert.Equal(t, want.grpcCode, status.Code(err))
			})
		}
	})
}
