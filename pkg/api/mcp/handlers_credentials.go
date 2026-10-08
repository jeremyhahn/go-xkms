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

package mcp

import (
	"context"
	"errors"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	credentialspkg "github.com/jeremyhahn/go-xkms/pkg/server/credentials"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// ErrXKMSServiceUnavailable is returned when the xkms service is not available.
var ErrXKMSServiceUnavailable = errors.New("xkms service unavailable")

// credentialSentinelCodes maps pkg/server/credentials' sentinel errors
// (reached through XKMSService.SubmitCredential and GetCredentialStrategy)
// onto JSON-RPC error codes. This domain has
// no gRPC transport at all to share a classification with, so it is
// classified locally.
var credentialSentinelCodes = []struct {
	sentinel error
	code     int
}{
	{credentialspkg.ErrEmptyCredentialName, ErrCodeInvalidParams},
	{credentialspkg.ErrEmptyCredentialValue, ErrCodeInvalidParams},
	{credentialspkg.ErrCredentialAlreadySubmitted, sdkssh.JSONRPCCodeDuplicate},
	{credentialspkg.ErrCredentialNotFound, sdkssh.JSONRPCCodeNotFound},
	// Credential submission is platform-scoped: a tenant-scoped caller is
	// refused with xkms.TenantBindingError, which unwraps to go-qrdb's
	// unknown-tenant sentinel and answers exactly as a genuine miss
	// (go-xkms#1226).
	{qrdbsdk.ErrTenantMissing, sdkssh.JSONRPCCodeNotFound},
	// ErrInvalidStrategy, ErrNilBarrier and
	// ErrNilPlatformStore report a server-side configuration or state fault
	// the caller cannot resolve by retrying with different parameters; they
	// fall to the ErrCodeInternalError default below, the same floor
	// FailedPrecondition sentinels use throughout this package.
	{xkms.ErrNilRequest, ErrCodeInvalidParams},
	{xkms.ErrInvalidEncoding, ErrCodeInvalidParams},
	{xkms.ErrNotConfigured, ErrCodeServiceUnavailable},
}

// mapCredentialError converts an error returned by the credential submission
// service into a *KeyOpError carrying the JSON-RPC code
// credentialSentinelCodes names for it. Anything not in that table is an
// internal fault.
func mapCredentialError(err error) error {
	if err == nil {
		return nil
	}
	for _, entry := range credentialSentinelCodes {
		if errors.Is(err, entry.sentinel) {
			return classified(entry.code, err)
		}
	}
	return &KeyOpError{Code: ErrCodeInternalError, Err: err}
}

// handleCredentialSubmit handles the credentials.submit method.
func (s *Server) handleCredentialSubmit(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc := s.xkmsService
	if svc == nil {
		return nil, errXKMSServiceUnavailable()
	}

	var params transport.CredentialSubmitRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	resp, err := svc.SubmitCredential(ctx, &params)
	if err != nil {
		return nil, mapCredentialError(err)
	}
	return resp, nil
}

// handleCredentialStrategy handles the credentials.strategy method.
func (s *Server) handleCredentialStrategy(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc := s.xkmsService
	if svc == nil {
		return nil, errXKMSServiceUnavailable()
	}

	resp, err := svc.GetCredentialStrategy(ctx)
	if err != nil {
		return nil, mapCredentialError(err)
	}
	return resp, nil
}
