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

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/api/apierrors"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// mapCustodianError converts an error returned by the xkms service layer's
// custodian-group operations into a *KeyOpError, classifying it through
// apierrors.CustodianSentinelClasses -- the table go-xkms#773 made this
// package share with pkg/api/grpc's mapCustodianError, following the
// go-xkms#912 precedent set for PIV and barrier. Anything not in that table
// is an internal fault.
func mapCustodianError(err error, operation string) error {
	if err == nil {
		return nil
	}
	if class, ok := apierrors.ClassOf(apierrors.CustodianSentinelClasses, err); ok {
		return classified(jsonRPCCodeForClass(class), &errs.Wrapped{Msg: operation, Err: err})
	}
	return &KeyOpError{Code: ErrCodeInternalError, Err: &errs.Wrapped{Msg: operation, Err: err}}
}

// tenantSentinelCodes maps the pkg/seal tenant/barrier domain errors and the
// xkms tenant-request validation sentinels onto JSON-RPC error codes,
// mirroring pkg/api/grpc/service_custodian_share_tenant.go's
// tenantErrorToGRPC.
var tenantSentinelCodes = []struct {
	sentinel error
	code     int
}{
	{seal.ErrTenantNotFound, sdkssh.JSONRPCCodeNotFound},
	{seal.ErrTenantAlreadyExists, sdkssh.JSONRPCCodeDuplicate},
	{seal.ErrEmptyTenantID, ErrCodeInvalidParams},
	{seal.ErrAlreadyInitialized, sdkssh.JSONRPCCodeDuplicate},
	{seal.ErrAlreadyUnsealed, sdkssh.JSONRPCCodeDuplicate},
	{seal.ErrNilSystemBarrier, ErrCodeServiceUnavailable},
	{xkms.ErrTenantPassphraseRequired, ErrCodeInvalidParams},
	{xkms.ErrTenantSharesRequired, ErrCodeInvalidParams},
	// JSON-RPC has no FailedPrecondition code; these fall to the same
	// internal floor mapKeyOpError's keyOpSentinelCodes doc explains.
	{seal.ErrSealed, ErrCodeInternalError},
	{seal.ErrNotInitialized, ErrCodeInternalError},
	{xkms.ErrTenantStrategyConflict, ErrCodeInternalError},
	{qrdbsdk.ErrSharedBarrierImmutable, ErrCodeInternalError},
}

// mapTenantError converts an error returned by the XKMSService tenant
// operations, or by refuseCrossTenantAdmin's anti-enumeration check, into a
// *KeyOpError, mirroring pkg/api/grpc/service_custodian_share_tenant.go's
// mapTenantError.
//
// Unlike PIN, PIV and barrier, tenant classification is not shared through
// pkg/api/apierrors: gRPC's mapTenantError does not classify from a plain
// sentinel table alone -- it type-asserts *qrdbsdk.EntitlementError and
// calls qrdbsdk.IsQuotaExceeded before ever consulting tenantErrorToGRPC --
// so a mechanical, message-preserving refactor into Sentinel -> Class would
// lose that behaviour. apierrors.go's own scoping comment excludes exactly
// this shape of classifier (the same reason mapPasswordError/mapCAError stay
// local); this function mirrors that exclusion for the same domain shape.
func mapTenantError(err error, operation string) error {
	if err == nil {
		return nil
	}

	var entErr *qrdbsdk.EntitlementError
	if errors.As(err, &entErr) {
		// Plan does not entitle the requested isolation/barrier mode or
		// feature, matching gRPC's codes.PermissionDenied for the same
		// *qrdbsdk.EntitlementError.
		return &KeyOpError{Code: ErrCodeForbidden, Err: &errs.Wrapped{Msg: operation, Err: err}}
	}
	if qrdbsdk.IsQuotaExceeded(err) {
		// Matches gRPC's codes.ResourceExhausted; JSON-RPC has no dedicated
		// member, so this renders through the same internal floor
		// apierrors.ClassResourceExhausted uses.
		return classified(ErrCodeInternalError, &errs.Wrapped{Msg: operation, Err: err})
	}

	for _, entry := range tenantSentinelCodes {
		if errors.Is(err, entry.sentinel) {
			return classified(entry.code, &errs.Wrapped{Msg: operation, Err: err})
		}
	}

	return &KeyOpError{Code: ErrCodeInternalError, Err: &errs.Wrapped{Msg: operation, Err: err}}
}
