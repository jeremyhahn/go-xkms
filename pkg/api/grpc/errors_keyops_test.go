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
	"errors"
	"testing"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-xkms/pkg/api/apierrors"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// TestGrpcCodeForClass_UnmappedClassFallsBackToInternal proves the
// documented floor: a Class classToGRPCCode has no row for (a future
// apierrors table addition this package has not yet caught up with) still
// renders as codes.Internal rather than the zero value of codes.Code, which
// happens to also be codes.OK -- an unmapped Class silently reporting
// success would be worse than reporting the wrong failure code.
func TestGrpcCodeForClass_UnmappedClassFallsBackToInternal(t *testing.T) {
	unmapped := apierrors.Class(999)
	if got := grpcCodeForClass(unmapped); got != codes.Internal {
		t.Fatalf("grpcCodeForClass(unmapped) = %v, want codes.Internal", got)
	}
}

// TestGrpcCodeForClass_MappedClasses spot-checks that every table entry
// resolves to its own code rather than all collapsing to the same fallback,
// which a bug returning codes.Internal unconditionally would not catch.
func TestGrpcCodeForClass_MappedClasses(t *testing.T) {
	tests := map[apierrors.Class]codes.Code{
		apierrors.ClassInvalidArgument:  codes.InvalidArgument,
		apierrors.ClassNotFound:         codes.NotFound,
		apierrors.ClassPermissionDenied: codes.PermissionDenied,
		apierrors.ClassUnavailable:      codes.Unavailable,
	}
	for class, want := range tests {
		if got := grpcCodeForClass(class); got != want {
			t.Errorf("grpcCodeForClass(%v) = %v, want %v", class, got, want)
		}
	}
}

// TestMapKeyOpError_ForwardsNotLeaderTranslation proves mapKeyOpError
// actually returns notLeaderStatus's translation rather than merely calling
// it and falling through to the generic keyOpSentinelCodes / codes.Internal
// handling below it. notLeaderStatus's own translation logic (the gRPC code,
// the ErrorInfo metadata) is pinned directly by
// TestNotLeaderStatus_Translation in errors_notleader_test.go; this proves
// only that mapKeyOpError's own early-return wires to it.
func TestMapKeyOpError_ForwardsNotLeaderTranslation(t *testing.T) {
	src := &qrdbtransport.NotLeaderError{ShardID: 1, LeaderID: 2, LeaderAddress: "10.0.0.2:63001"}
	err := mapKeyOpError(context.Background(), nil, &errs.Wrapped{Msg: "sign", Err: src})

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("mapKeyOpError did not return a gRPC status error for a not-leader error")
	}
	if st.Code() != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition (the not-leader translation), not the generic %v mapping",
			st.Code(), codes.Internal)
	}
}

// TestMapImportExportError_UnclassifiedErrorFallsBackToInternal proves the
// documented fallback for mapImportExportError: an error absent from
// apierrors.ImportExportSentinelClasses renders as codes.Internal with msg
// as a prefix, matching the %v-formatted messages the pre-table call sites
// used.
func TestMapImportExportError_UnclassifiedErrorFallsBackToInternal(t *testing.T) {
	err := mapImportExportError("export key", errors.New("disk on fire"))
	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("mapImportExportError did not return a gRPC status error")
	}
	if st.Code() != codes.Internal {
		t.Fatalf("code = %v, want codes.Internal for an unclassified error", st.Code())
	}
	if got := st.Message(); got != "export key: disk on fire" {
		t.Fatalf("message = %q, want %q", got, "export key: disk on fire")
	}
}
