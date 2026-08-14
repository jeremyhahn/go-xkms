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

	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

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
	{xkms.ErrOperationNotSupported, codes.Unimplemented},
	{xkms.ErrExportKeyMaterialFailed, codes.FailedPrecondition},
	{xkms.ErrBackendNotFound, codes.NotFound},
	{xkms.ErrKeyNotFound, codes.NotFound},
	{xkms.ErrNotInitialized, codes.Unavailable},
}

// mapKeyOpError converts an error returned by the xkms service layer into a
// gRPC status error. Validation failures report the offending field verbatim so
// callers see the same wire-level field name they sent; capability boundaries
// (a backend that cannot attest, or cannot export) become Unimplemented or
// FailedPrecondition; unresolved backends and keys become NotFound. Anything
// else is an internal fault. xkmsService is threaded through to notLeaderStatus
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

	var validation *xkms.ErrValidation
	if errors.As(err, &validation) {
		return status.Error(codes.InvalidArgument, validationMessage(validation))
	}

	for _, entry := range keyOpSentinelCodes {
		if errors.Is(err, entry.sentinel) {
			return status.Error(entry.code, err.Error())
		}
	}

	return status.Error(codes.Internal, err.Error())
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
