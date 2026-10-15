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
	"github.com/jeremyhahn/go-xkms/pkg/api/apierrors"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// classToJSONRPCCode translates apierrors.Class onto this transport's
// JSON-RPC error code. It is total over every Class the apierrors tables
// this package reads (ImportExportSentinelClasses, AEADSentinelClasses,
// PIVSentinelClasses, PINSentinelClasses,
// SealStoreSentinelClasses, and TPMPolicyClassOf)
// can produce;
// jsonRPCCodeForClass's ErrCodeInternalError floor exists only for a Class a
// future apierrors table introduces without a row here.
//
// The JSON-RPC 2.0 vocabulary is far coarser than gRPC's codes.Code: it has
// no dedicated AlreadyExists, PermissionDenied, FailedPrecondition,
// Unauthenticated, DataLoss or DeadlineExceeded member. Where this package's
// SSH sub-system already minted a reserved-range code for the identical
// outcome (errors_ssh.go, sdk/go/client/ssh/mcp_status.go), that code is
// reused rather than inventing a second one for the same wire condition;
// where nothing closer exists, the entry falls back to a code whose
// classifyToolError -> wire.Code rendering (pkg/apimodule/module_mcp_errors.go)
// is the least misleading available: ErrCodeForbidden for a caller that is
// authenticated but not entitled (PermissionDenied), ErrCodeServiceUnavailable
// for a capability that is not wired up (Unavailable), and
// ErrCodeInternalError for the rest, exactly as pkg/api/mcp's other sentinel
// tables (keyOpSentinelCodes) already do for the same gap.
var classToJSONRPCCode = map[apierrors.Class]int{
	apierrors.ClassInternal:           ErrCodeInternalError,
	apierrors.ClassInvalidArgument:    ErrCodeInvalidParams,
	apierrors.ClassNotFound:           sdkssh.JSONRPCCodeNotFound,
	apierrors.ClassAlreadyExists:      sdkssh.JSONRPCCodeDuplicate,
	apierrors.ClassPermissionDenied:   ErrCodeForbidden,
	apierrors.ClassFailedPrecondition: ErrCodeInternalError,
	apierrors.ClassUnavailable:        ErrCodeServiceUnavailable,
	apierrors.ClassUnimplemented:      ErrCodeMethodNotFound,
	apierrors.ClassUnauthenticated:    ErrCodeInvalidParams,
	apierrors.ClassDataLoss:           ErrCodeInternalError,
	apierrors.ClassDeadlineExceeded:   ErrCodeInternalError,
	// ClassResourceExhausted (a PIN backend locked out after too many failed
	// attempts) has no dedicated JSON-RPC member either; it renders through
	// the same floor ClassFailedPrecondition already uses.
	apierrors.ClassResourceExhausted: ErrCodeInternalError,
}

// jsonRPCCodeForClass renders an apierrors.Class as its JSON-RPC error code,
// falling back to ErrCodeInternalError for a Class classToJSONRPCCode does
// not cover.
func jsonRPCCodeForClass(c apierrors.Class) int {
	if code, ok := classToJSONRPCCode[c]; ok {
		return code
	}
	return ErrCodeInternalError
}

// mapImportExportError converts an error returned directly by a
// backend.ImportBackend / backend.ExportBackend method into a *KeyOpError,
// classifying the capability sentinels in
// apierrors.ImportExportSentinelClasses -- the table go-xkms#912 made this
// package share with pkg/api/grpc's mapImportExportError -- and falling back
// to ErrCodeInternalError for anything else. handleWrapKey, handleUnwrapKey
// and handleExportKey call these backend methods directly rather than
// through the xkms service layer, so mapKeyOpError's xkms.* sentinel table
// does not apply to them; before this existed every backend refusal from
// these handlers -- including the exact capability boundaries this project
// asks a backend to report precisely, such as AWS KMS's
// ErrExportNotSupported -- was flattened to ErrCodeInternalError.
func mapImportExportError(msg string, err error) error {
	if err == nil {
		return nil
	}
	if class, ok := apierrors.ClassOf(apierrors.ImportExportSentinelClasses, err); ok {
		return classified(jsonRPCCodeForClass(class), &errs.Wrapped{Msg: msg, Err: err})
	}
	return &KeyOpError{Code: ErrCodeInternalError, Err: &errs.Wrapped{Msg: msg, Err: err}}
}

// mapPIVError converts a PIV domain error into a *KeyOpError, classifying it
// through apierrors.PIVSentinelClasses -- the table go-xkms#912 made this
// package share with pkg/api/grpc's mapPIVError. Anything not in that table
// is an internal fault.
func mapPIVError(err error, operation string) error {
	if err == nil {
		return nil
	}
	if class, ok := apierrors.ClassOf(apierrors.PIVSentinelClasses, err); ok {
		return classified(jsonRPCCodeForClass(class), &errs.Wrapped{Msg: operation, Err: err})
	}
	return &KeyOpError{Code: ErrCodeInternalError, Err: &errs.Wrapped{Msg: operation, Err: err}}
}

// mapPINError converts a PIN domain error into a *KeyOpError, classifying it
// through apierrors.PINSentinelClasses -- the table go-xkms#773 made this
// package share with pkg/api/grpc/service_pin.go's mapPINError,
// following the go-xkms#912 precedent set for PIV and barrier. Anything not
// in that table is an internal fault.
func mapPINError(err error, operation string) error {
	if err == nil {
		return nil
	}
	if class, ok := apierrors.ClassOf(apierrors.PINSentinelClasses, err); ok {
		return classified(jsonRPCCodeForClass(class), &errs.Wrapped{Msg: operation, Err: err})
	}
	return &KeyOpError{Code: ErrCodeInternalError, Err: &errs.Wrapped{Msg: operation, Err: err}}
}

// mapClassifiedError converts an API error into a *KeyOpError, classifying
// it through classOf -- an apierrors *ClassOf function, the classification
// pkg/api/grpc and pkg/api/rest read for the same API. Anything it does not
// classify is an internal fault.
func mapClassifiedError(err error, operation string, classOf func(error) (apierrors.Class, bool)) error {
	if err == nil {
		return nil
	}
	if class, ok := classOf(err); ok {
		return classified(jsonRPCCodeForClass(class), &errs.Wrapped{Msg: operation, Err: err})
	}
	return &KeyOpError{Code: ErrCodeInternalError, Err: &errs.Wrapped{Msg: operation, Err: err}}
}

// mapTPMPolicyError converts a TPM policy API error into a *KeyOpError
// through apierrors.TPMPolicyClassOf.
func mapTPMPolicyError(err error, operation string) error {
	return mapClassifiedError(err, operation, apierrors.TPMPolicyClassOf)
}

// mapOIDCCredentialError converts an OIDC credential API error into a
// *KeyOpError through apierrors.OIDCCredentialClassOf.
func mapOIDCCredentialError(err error, operation string) error {
	return mapClassifiedError(err, operation, apierrors.OIDCCredentialClassOf)
}

// mapPeerAttestationError converts an attested-caller verb's error into a
// *KeyOpError through apierrors.PeerAttestationClassOf.
func mapPeerAttestationError(err error, operation string) error {
	return mapClassifiedError(err, operation, apierrors.PeerAttestationClassOf)
}
