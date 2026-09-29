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

	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// mapCAError converts an error from a pkg/ca-backed CA operation
// (GetCABundle, GetCACertificate, SignCSR, IssueCertificate,
// RevokeCertificate, GenerateCRL, IsRevoked, and the TCG device-enrollment
// family in handlers_ca_tcg.go) into a *KeyOpError.
//
// pkg/api/grpc's CA handlers have no sentinel table to share here either:
// each RPC pre-validates its own required fields (InvalidArgument) and
// separately checks its package-level CA instance for nil before ever
// calling the servicer (Unavailable), then reports any servicer failure as a
// fixed codes.Internal (service_ca.go). This package's CA handlers call the
// servicer directly with no pre-validation step of their own, so the
// service-layer sentinels that check take the place of gRPC's request-field
// validation, mapped onto the same two non-Internal outcomes gRPC uses:
// xkms.ErrNotConfigured -- returned by XKMSService.getCA when no CA is
// wired -- is Service unavailable, matching gRPC's Unavailable-for-nil-CA
// check; a validation failure (*xkms.ErrValidation, xkms.ErrNilRequest,
// xkms.ErrNilData) is Invalid params, matching gRPC's pre-validation. Every
// other error, including a wrapped *xkms.ErrCAOperation, is internal,
// matching gRPC's fallback.
func mapCAError(err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, xkms.ErrNotConfigured) {
		return &KeyOpError{Code: ErrCodeServiceUnavailable, Err: err}
	}

	var validation *xkms.ErrValidation
	if errors.As(err, &validation) {
		return &KeyOpError{Code: ErrCodeInvalidParams, Err: validation}
	}

	if errors.Is(err, xkms.ErrNilRequest) || errors.Is(err, xkms.ErrNilData) {
		return &KeyOpError{Code: ErrCodeInvalidParams, Err: err}
	}

	// SignCSR's SPIFFE tenant is caller-supplied; the service's tenant
	// binding refuses a foreign one as not-found (xkms.TenantBindingError).
	if errors.Is(err, qrdbsdk.ErrTenantMissing) {
		return &KeyOpError{Code: sdkssh.JSONRPCCodeNotFound, Err: err}
	}

	return &KeyOpError{Code: ErrCodeInternalError, Err: err}
}
