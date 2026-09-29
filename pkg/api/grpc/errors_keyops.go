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

package grpc

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-xkms/pkg/api/apierrors"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// classToGRPCCode translates apierrors.Class onto its gRPC status code. It is
// total over every Class the apierrors tables this package reads
// (ImportExportSentinelClasses, and the PIV, barrier, seal store, PIN,
// custodian and policy tables consumed by service_piv.go,
// service_barrier_pin.go, service_seal_store.go,
// service_custodian_share_tenant.go and service_policy.go) can produce, so
// a table entry can never resolve to an unmapped Class silently;
// grpcCodeForClass's codes.Internal floor exists only for a Class a future
// apierrors table introduces without a row here.
var classToGRPCCode = map[apierrors.Class]codes.Code{
	apierrors.ClassInternal:           codes.Internal,
	apierrors.ClassInvalidArgument:    codes.InvalidArgument,
	apierrors.ClassNotFound:           codes.NotFound,
	apierrors.ClassAlreadyExists:      codes.AlreadyExists,
	apierrors.ClassPermissionDenied:   codes.PermissionDenied,
	apierrors.ClassFailedPrecondition: codes.FailedPrecondition,
	apierrors.ClassUnavailable:        codes.Unavailable,
	apierrors.ClassUnimplemented:      codes.Unimplemented,
	apierrors.ClassUnauthenticated:    codes.Unauthenticated,
	apierrors.ClassDataLoss:           codes.DataLoss,
	apierrors.ClassDeadlineExceeded:   codes.DeadlineExceeded,
	apierrors.ClassResourceExhausted:  codes.ResourceExhausted,
}

// grpcCodeForClass renders an apierrors.Class as its gRPC status code,
// falling back to codes.Internal for a Class classToGRPCCode does not cover.
func grpcCodeForClass(c apierrors.Class) codes.Code {
	if code, ok := classToGRPCCode[c]; ok {
		return code
	}
	return codes.Internal
}

// keyOpSentinelCodes maps the service-layer sentinels raised by the key and
// crypto operations onto gRPC status codes. It is an ordered slice rather than
// a map because a single error can satisfy errors.Is for more than one entry:
// xkms.ErrOperationWrap deliberately exposes both its sentinel and its cause.
// The first match wins, so the most specific sentinel is listed first.
var keyOpSentinelCodes = []struct {
	sentinel error
	code     codes.Code
}{
	// A digest this service refuses (SHA-1 and the other collision-broken
	// names) or cannot resolve is a fault in the request, not in the server.
	// ResolveOAEPHash reports the weak-hash refusal as ErrOperationWrap rather
	// than ErrValidation, so without these two entries it fell through to the
	// catch-all and a caller that named a bad digest was told the server had
	// failed.
	{xkms.ErrWeakOAEPHash, codes.InvalidArgument},
	{xkms.ErrInvalidHashFunction, codes.InvalidArgument},
	// A malformed certificate, an empty chain, or sealed data missing its
	// payload is a fault in the request (go-xkms#1228).
	{xkms.ErrInvalidEncodingPEM, codes.InvalidArgument},
	{xkms.ErrInvalidCertificate, codes.InvalidArgument},
	{xkms.ErrEmptyChain, codes.InvalidArgument},
	{xkms.ErrInvalidSealedData, codes.InvalidArgument},
	{xkms.ErrNilData, codes.InvalidArgument},
	{xkms.ErrOperationNotSupported, codes.Unimplemented},
	{xkms.ErrSealingNotSupported, codes.Unimplemented},
	{xkms.ErrExportKeyMaterialFailed, codes.FailedPrecondition},
	{xkms.ErrBackendNotFound, codes.NotFound},
	{xkms.ErrKeyNotFound, codes.NotFound},
	{xkms.ErrCertNotFound, codes.NotFound},
	{xkms.ErrCertChainNotFound, codes.NotFound},
	{storage.ErrNotFound, codes.NotFound},
	{xkms.ErrNotInitialized, codes.Unavailable},
}

// mapKeyOpError converts an error returned by the xkms service layer into a
// gRPC status error. Validation failures report the offending field verbatim so
// callers see the same wire-level field name they sent; a malformed backend
// name is InvalidArgument; capability boundaries (a backend that cannot
// attest, or cannot export) become Unimplemented or FailedPrecondition;
// unresolved backends and keys become NotFound. A backend-layer import/export
// sentinel the service wraps as an operation failure's cause -- ExportKey and
// CopyKey report ErrKeyNotExportable and ErrExportNotSupported that way -- is
// classified by apierrors.ImportExportSentinelClasses, exactly as
// mapImportExportError classifies it. Anything else is an internal fault. xkmsService is threaded through to notLeaderStatus
// so a not-leader translation can resolve the leader's dialable gRPC endpoint;
// it may be nil.
func mapKeyOpError(ctx context.Context, xkmsService *xkms.XKMSService, err error) error {
	if err == nil {
		return nil
	}

	if translated, ok := notLeaderStatus(ctx, xkmsService, err); ok {
		return translated
	}

	var role *xkms.ErrRoleLookup
	if errors.As(err, &role) {
		return status.Error(codes.NotFound, role.Error())
	}

	// A key or certificate ID that does not parse -- including one naming
	// another tenant's namespace ("tenant-b/web") -- is malformed input. It
	// is matched before ErrValidation, which the parse failure may wrap, so
	// the message names the key ID as the field at fault.
	var keyID *xkms.ErrKeyIDParse
	if errors.As(err, &keyID) {
		return status.Error(codes.InvalidArgument, keyID.Error())
	}

	var validation *xkms.ErrValidation
	if errors.As(err, &validation) {
		return status.Error(codes.InvalidArgument, validationMessage(validation))
	}

	var backendName *xkms.ErrBackendNameValidation
	if errors.As(err, &backendName) {
		return status.Error(codes.InvalidArgument, backendName.Error())
	}

	for _, entry := range keyOpSentinelCodes {
		if errors.Is(err, entry.sentinel) {
			return status.Error(entry.code, err.Error())
		}
	}

	if class, ok := apierrors.ClassOf(apierrors.ImportExportSentinelClasses, err); ok {
		return status.Error(grpcCodeForClass(class), err.Error())
	}

	return status.Error(codes.Internal, err.Error())
}

// mapImportExportError converts an error returned directly by a
// backend.ImportBackend / backend.ExportBackend method into a gRPC status
// error, classifying the capability sentinels in
// apierrors.ImportExportSentinelClasses -- the table go-xkms#912 made this
// package share with pkg/api/mcp's mirror of this function -- and falling
// back to codes.Internal (with msg as a prefix, matching the %v-formatted
// messages these call sites used before this existed) for anything else.
// WrapKey, UnwrapKey, GetImportParameters, ImportKey, ExportKey and CopyKey
// call the backend.ImportBackend / backend.ExportBackend methods directly
// rather than through the xkms service layer (their own doc comments explain
// why: the service layer's versions drop fields these RPCs need), so
// mapKeyOpError's xkms.* sentinel table does not apply to them. Without this
// table, every backend refusal from these calls -- including the exact
// capability boundaries this project asks a backend to report precisely,
// such as AWS KMS's ErrExportNotSupported -- was flattened to codes.Internal.
func mapImportExportError(msg string, err error) error {
	if class, ok := apierrors.ClassOf(apierrors.ImportExportSentinelClasses, err); ok {
		return status.Errorf(grpcCodeForClass(class), "%s: %v", msg, err)
	}
	return status.Errorf(codes.Internal, "%s: %v", msg, err)
}

// validationMessage renders a service-layer validation error for the wire. The
// Detail carries the caller-facing message ("key_id is required"); the sentinel
// is only used when a validation error carries no detail.
func validationMessage(err *xkms.ErrValidation) string {
	if err.Detail != "" {
		return err.Detail
	}
	return err.Sentinel.Error()
}
