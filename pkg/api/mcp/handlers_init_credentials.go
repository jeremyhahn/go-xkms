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

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	initialize "github.com/jeremyhahn/go-xkms/pkg/init"
	credentialspkg "github.com/jeremyhahn/go-xkms/pkg/server/credentials"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// ErrXKMSServiceUnavailable is returned when the xkms service is not available.
var ErrXKMSServiceUnavailable = errors.New("xkms service unavailable")

// ErrClientCertRequired is returned when a share-claim method is invoked over
// a session that carries no verified mTLS peer certificate. The officer's
// certificate thumbprint is the authentication for these methods.
var ErrClientCertRequired = errors.New("client certificate required")

// ceremonySentinelCodes maps the go-init ceremony domain's sentinels
// (pkg/init's initialize.Err*, reached through XKMSService.GetInitStatus,
// ClaimCertBegin, ClaimCertComplete, ClaimShareBegin, ClaimShareComplete and
// SignCSRInit) onto JSON-RPC error codes.
//
// None of these six endpoints exist on the gRPC transport at all --
// pkg/api/transport/grpc/transport.go's versions each return ErrNotSupported
// unconditionally, with a doc comment noting the endpoint is REST/MCP-only --
// so unlike the import/export, PIV, barrier and seal-store families
// (go-xkms#912, #921) there is no gRPC classification for this package to
// share through pkg/api/apierrors. REST is this domain's actual sibling
// transport (pkg/api/rest/handlers_init.go's initErrorStatusMap); this table
// carries the SAME semantic classification onto the coarser JSON-RPC
// vocabulary: REST's 404s become sdkssh.JSONRPCCodeNotFound, its 409
// "already claimed/initialized" conflicts become sdkssh.JSONRPCCodeDuplicate,
// its 401 challenge/PIN failures become ErrCodeUnauthorized, its 400
// malformed-request rejections become ErrCodeInvalidParams, and its 503 "CA
// not initialized" becomes ErrCodeServiceUnavailable, matching this
// package's own xkms.ErrNotConfigured floor. REST's remaining 409 (wrong
// ceremony state) and 410 (expired challenge) have no JSON-RPC counterpart
// and fall to ErrCodeInternalError, the same floor
// pkg/api/mcp/errors_keyops.go's keyOpSentinelCodes already uses for
// FailedPrecondition.
var ceremonySentinelCodes = []struct {
	sentinel error
	code     int
}{
	{initialize.ErrPendingCertNotFound, sdkssh.JSONRPCCodeNotFound},
	{initialize.ErrCertAlreadyClaimed, sdkssh.JSONRPCCodeDuplicate},
	{initialize.ErrShareNotFound, sdkssh.JSONRPCCodeNotFound},
	{initialize.ErrShareAlreadyClaimed, sdkssh.JSONRPCCodeDuplicate},
	{initialize.ErrChallengeVerificationFailed, ErrCodeUnauthorized},
	{initialize.ErrCertThumbprintMismatch, ErrCodeUnauthorized},
	{initialize.ErrOfficerNotFound, sdkssh.JSONRPCCodeNotFound},
	{initialize.ErrNoPendingShare, sdkssh.JSONRPCCodeNotFound},
	{initialize.ErrAlreadyInitialized, sdkssh.JSONRPCCodeDuplicate},
	{initialize.ErrUserNotFound, sdkssh.JSONRPCCodeNotFound},
	{initialize.ErrChallengeNotFound, sdkssh.JSONRPCCodeNotFound},
	{initialize.ErrChallengeExpired, ErrCodeInternalError},
	{initialize.ErrNotInEnrollingState, ErrCodeInternalError},
	{initialize.ErrNotInitializedOrEnrolling, ErrCodeInternalError},
	{initialize.ErrSOPINMismatch, ErrCodeUnauthorized},
	{initialize.ErrInvalidSOPIN, ErrCodeInvalidParams},
	{initialize.ErrMissingCSRPEM, ErrCodeInvalidParams},
	{initialize.ErrMissingUsername, ErrCodeInvalidParams},
	{initialize.ErrMissingRole, ErrCodeInvalidParams},
	{initialize.ErrInvalidRole, ErrCodeInvalidParams},
	{initialize.ErrInvalidCSR, ErrCodeInvalidParams},
	{initialize.ErrCANotInitialized, ErrCodeServiceUnavailable},
	{initialize.ErrCSRSigningFailed, ErrCodeInternalError},
	{xkms.ErrNilRequest, ErrCodeInvalidParams},
	{xkms.ErrNotConfigured, ErrCodeServiceUnavailable},
}

// mapCeremonyError converts an error returned by the init ceremony service
// into a *KeyOpError carrying the JSON-RPC code ceremonySentinelCodes names
// for it. Anything not in that table is an internal fault.
func mapCeremonyError(err error) error {
	if err == nil {
		return nil
	}
	for _, entry := range ceremonySentinelCodes {
		if errors.Is(err, entry.sentinel) {
			return &KeyOpError{Code: entry.code, Err: err}
		}
	}
	return &KeyOpError{Code: ErrCodeInternalError, Err: err}
}

// credentialSentinelCodes maps pkg/server/credentials' sentinel errors
// (reached through XKMSService.SubmitCredential and GetCredentialStrategy)
// onto JSON-RPC error codes. Like the ceremony family above, this domain has
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
	// ErrManualEntryRequired, ErrInvalidStrategy, ErrNilBarrier and
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
			return &KeyOpError{Code: entry.code, Err: err}
		}
	}
	return &KeyOpError{Code: ErrCodeInternalError, Err: err}
}

// handleGetInitStatus handles the init.getStatus method.
func (s *Server) handleGetInitStatus(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc := s.xkmsService
	if svc == nil {
		return nil, errXKMSServiceUnavailable()
	}
	resp, err := svc.GetInitStatus(ctx)
	if err != nil {
		return nil, mapCeremonyError(err)
	}
	return resp, nil
}

// handleClaimCertBegin handles the init.claimCertBegin method.
func (s *Server) handleClaimCertBegin(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc := s.xkmsService
	if svc == nil {
		return nil, errXKMSServiceUnavailable()
	}

	var params transport.ClaimCertBeginRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	resp, err := svc.ClaimCertBegin(ctx, &params)
	if err != nil {
		return nil, mapCeremonyError(err)
	}
	return resp, nil
}

// handleClaimCertComplete handles the init.claimCertComplete method.
func (s *Server) handleClaimCertComplete(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc := s.xkmsService
	if svc == nil {
		return nil, errXKMSServiceUnavailable()
	}

	var params transport.ClaimCertCompleteRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	resp, err := svc.ClaimCertComplete(ctx, &params)
	if err != nil {
		return nil, mapCeremonyError(err)
	}
	return resp, nil
}

// callerCertThumbprint derives the caller's certificate thumbprint from the
// verified mTLS peer chain carried on the connection context by the MCP
// server's handshake path. It fails closed with a *KeyOpError wrapping
// ErrClientCertRequired when the session carries no peer certificate, so the
// share-claim methods never fall back to trusting a username.
//
// The code is ErrCodeUnauthorized (wire.CodeUnauthenticated), matching
// REST's 401 for the same refusal (pkg/api/rest/handlers_init.go): the
// caller has not presented the credential this step authenticates with.
//
// The value is computed with initialize.CertThumbprint, the single canonical
// binding identifier the ceremony records for each officer at enrollment.
func callerCertThumbprint(ctx context.Context) (string, error) {
	state := auth.TLSStateFromContext(ctx)
	if state == nil || len(state.PeerCertificates) == 0 {
		return "", &KeyOpError{Code: ErrCodeUnauthorized, Err: ErrClientCertRequired}
	}
	return initialize.CertThumbprint(state.PeerCertificates[0].Raw), nil
}

// handleClaimShareBegin handles the init.claimShareBegin method. The officer
// has no account yet; the certificate claim-cert issued them is their
// credential, and its thumbprint is the authentication here.
func (s *Server) handleClaimShareBegin(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc := s.xkmsService
	if svc == nil {
		return nil, errXKMSServiceUnavailable()
	}

	thumbprint, err := callerCertThumbprint(ctx)
	if err != nil {
		return nil, err
	}

	var params transport.ClaimShareBeginRequest
	if decErr := decodeParams(req, &params); decErr != nil {
		return nil, decErr
	}
	// Never from the wire: overwrite whatever decoding produced.
	params.CallerCertThumbprint = thumbprint

	resp, err := svc.ClaimShareBegin(ctx, &params)
	if err != nil {
		return nil, mapCeremonyError(err)
	}
	return resp, nil
}

// handleClaimShareComplete handles the init.claimShareComplete method,
// releasing the share exactly once after both the nonce signature and the
// caller certificate thumbprint verify.
func (s *Server) handleClaimShareComplete(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc := s.xkmsService
	if svc == nil {
		return nil, errXKMSServiceUnavailable()
	}

	thumbprint, err := callerCertThumbprint(ctx)
	if err != nil {
		return nil, err
	}

	var params transport.ClaimShareCompleteRequest
	if decErr := decodeParams(req, &params); decErr != nil {
		return nil, decErr
	}
	params.CallerCertThumbprint = thumbprint

	resp, err := svc.ClaimShareComplete(ctx, &params)
	if err != nil {
		return nil, mapCeremonyError(err)
	}
	return resp, nil
}

// handleSignCSRInit handles the init.signCSR method.
func (s *Server) handleSignCSRInit(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc := s.xkmsService
	if svc == nil {
		return nil, errXKMSServiceUnavailable()
	}

	var params transport.SignCSRInitRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	resp, err := svc.SignCSRInit(ctx, &params)
	if err != nil {
		return nil, mapCeremonyError(err)
	}
	return resp, nil
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
