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

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// Barrier parameter types for JSON-RPC requests.

// BarrierInitializeParams represents parameters for barrier initialization.
type BarrierInitializeParams struct {
	Secret string `json:"secret"`
}

// BarrierInitializeShamirParams represents parameters for Shamir barrier initialization.
type BarrierInitializeShamirParams struct {
	Secret string `json:"secret,omitempty"`
}

// BarrierUnsealParams represents parameters for barrier unsealing with a secret.
type BarrierUnsealParams struct {
	Secret string `json:"secret"`
}

// BarrierUnsealShareParams represents parameters for submitting a single share.
type BarrierUnsealShareParams struct {
	Share string `json:"share"`
}

// BarrierUnsealSharesParams represents parameters for batch share submission.
type BarrierUnsealSharesParams struct {
	Shares []string `json:"shares"`
}

// BarrierRekeyParams represents parameters for barrier rekey operation.
type BarrierRekeyParams struct {
	Threshold int `json:"threshold"`
	Total     int `json:"total"`
}

// BarrierGenerateRecoveryKeysParams represents parameters for recovery key generation.
type BarrierGenerateRecoveryKeysParams struct {
	Threshold int `json:"threshold"`
	Total     int `json:"total"`
}

// BarrierRecoverWithKeysParams represents parameters for recovery using keys.
type BarrierRecoverWithKeysParams struct {
	Keys []string `json:"keys"`
}

// BarrierGenerateRootTokenParams represents parameters for root token generation.
type BarrierGenerateRootTokenParams struct {
	Shares []string `json:"shares"`
}

// barrierService returns the composed XKMSService, or the Service
// unavailable error a barrier method answers when none is composed. Every
// system-barrier method delegates to the service: the system barrier is
// platform-global, and the service's requirePlatformScope is what refuses a
// tenant-scoped caller (go-xkms#1227). The RBAC gate cannot, because a
// tenant-local Admin's self-scoped seal:* grants resolve against its own
// tenant.
func (s *Server) barrierService() (*xkms.XKMSService, error) {
	if s.xkmsService == nil {
		return nil, &KeyOpError{Code: ErrCodeServiceUnavailable, Err: ErrBarrierNotConfigured}
	}
	return s.xkmsService, nil
}

// barrierValidationError classifies a request-field validation failure this
// transport checks itself (a missing secret/share/shares, or a threshold or
// total out of range) as Invalid params, mirroring the InvalidArgument every
// equivalent inline check in pkg/api/grpc/service_barrier_pin.go and
// service_barrier_shamir.go reports for the same condition.
func barrierValidationError(err error) error {
	return &KeyOpError{Code: ErrCodeInvalidParams, Err: err}
}

// handleBarrierInitialize handles the barrier.initialize method.
// It initializes the barrier with a secret-based sealing strategy.
func (s *Server) handleBarrierInitialize(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc, err := s.barrierService()
	if err != nil {
		return nil, err
	}
	var params BarrierInitializeParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	if params.Secret == "" {
		return nil, barrierValidationError(ErrBarrierSecretRequired)
	}
	if err := svc.BarrierInitialize(ctx, &transport.BarrierInitializeRequest{Secret: params.Secret}); err != nil {
		return nil, mapBarrierError(err, "barrier initialize")
	}
	return map[string]interface{}{
		"success": true,
		"message": "barrier initialized",
	}, nil
}

// handleBarrierInitializeShamir handles the barrier.initializeShamir method.
// It initializes the barrier with Shamir secret sharing. Share material is
// never returned: shares are sealed to enrolled Security Officers via the
// CeremonyDistributor (qrdb share-free contract) and only the threshold,
// total, and officer share count are reported.
func (s *Server) handleBarrierInitializeShamir(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc, err := s.barrierService()
	if err != nil {
		return nil, err
	}
	var params BarrierInitializeShamirParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	result, err := svc.BarrierInitializeShamir(ctx, &transport.BarrierInitializeShamirRequest{Secret: params.Secret})
	if err != nil {
		return nil, mapBarrierError(err, "barrier initialize shamir")
	}
	return map[string]interface{}{
		"success":      true,
		"threshold":    result.Threshold,
		"total_shares": result.TotalShares,
		"share_count":  result.ShareCount,
	}, nil
}

// handleBarrierUnseal handles the barrier.unseal method.
// It unseals the barrier using a secret credential.
func (s *Server) handleBarrierUnseal(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc, err := s.barrierService()
	if err != nil {
		return nil, err
	}
	var params BarrierUnsealParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	if params.Secret == "" {
		return nil, barrierValidationError(ErrBarrierSecretRequired)
	}
	if err := svc.BarrierUnseal(ctx, &transport.BarrierUnsealRequest{Secret: params.Secret}); err != nil {
		return nil, mapBarrierError(err, "barrier unseal")
	}
	return map[string]interface{}{
		"success": true,
		"message": "barrier unsealed",
	}, nil
}

// handleBarrierUnsealShare handles the barrier.unsealShare method.
// It submits a single Shamir share for quorum-based unsealing.
func (s *Server) handleBarrierUnsealShare(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc, err := s.barrierService()
	if err != nil {
		return nil, err
	}
	var params BarrierUnsealShareParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	if params.Share == "" {
		return nil, barrierValidationError(ErrBarrierShareRequired)
	}
	progress, err := svc.BarrierUnsealWithShare(ctx, &transport.BarrierUnsealShareRequest{Share: params.Share})
	if err != nil {
		return nil, mapBarrierError(err, "barrier unseal share")
	}
	return map[string]interface{}{
		"required":  progress.Required,
		"submitted": progress.Submitted,
		"complete":  progress.Complete,
	}, nil
}

// handleBarrierUnsealShares handles the barrier.unsealShares method.
// It performs batch unsealing with all required shares at once.
func (s *Server) handleBarrierUnsealShares(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc, err := s.barrierService()
	if err != nil {
		return nil, err
	}
	var params BarrierUnsealSharesParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	if len(params.Shares) == 0 {
		return nil, barrierValidationError(ErrBarrierSharesRequired)
	}
	if err := svc.BarrierUnsealWithShares(ctx, &transport.BarrierUnsealSharesRequest{Shares: params.Shares}); err != nil {
		return nil, mapBarrierError(err, "barrier unseal shares")
	}
	return map[string]interface{}{
		"success": true,
		"message": "barrier unsealed with shares",
	}, nil
}

// handleBarrierSeal handles the barrier.seal method.
// It transitions the barrier to sealed state.
func (s *Server) handleBarrierSeal(ctx context.Context, _ *JSONRPCRequest) (interface{}, error) {
	svc, err := s.barrierService()
	if err != nil {
		return nil, err
	}
	if err := svc.BarrierSeal(ctx); err != nil {
		return nil, mapBarrierError(err, "barrier seal")
	}
	return map[string]interface{}{
		"success": true,
		"message": "barrier sealed",
	}, nil
}

// handleBarrierStatus handles the barrier.status method.
// It returns the current barrier status.
func (s *Server) handleBarrierStatus(ctx context.Context, _ *JSONRPCRequest) (interface{}, error) {
	svc, err := s.barrierService()
	if err != nil {
		return nil, err
	}
	status, err := svc.BarrierStatus(ctx)
	if err != nil {
		return nil, mapBarrierError(err, "barrier status")
	}
	return map[string]interface{}{
		"sealed":          status.Sealed,
		"strategy":        status.Strategy,
		"hardware_backed": status.HardwareBacked,
	}, nil
}

// handleBarrierRekey handles the barrier.rekey method.
// It generates new Shamir shares with a new threshold and total.
func (s *Server) handleBarrierRekey(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc, err := s.barrierService()
	if err != nil {
		return nil, err
	}
	var params BarrierRekeyParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	if params.Threshold < 2 {
		return nil, barrierValidationError(ErrBarrierThresholdInvalid)
	}
	if params.Total < params.Threshold {
		return nil, barrierValidationError(ErrBarrierTotalInvalid)
	}
	result, err := svc.BarrierRekey(ctx, &transport.BarrierRekeyRequest{Threshold: params.Threshold, Total: params.Total})
	if err != nil {
		return nil, mapBarrierError(err, "barrier rekey")
	}
	return map[string]interface{}{
		"success":      true,
		"threshold":    result.Threshold,
		"total_shares": result.TotalShares,
		"share_count":  result.ShareCount,
	}, nil
}

// handleBarrierGenerateRecoveryKeys handles the barrier.generateRecoveryKeys method.
// It generates a set of recovery key shares for disaster recovery.
func (s *Server) handleBarrierGenerateRecoveryKeys(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc, err := s.barrierService()
	if err != nil {
		return nil, err
	}
	var params BarrierGenerateRecoveryKeysParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	if params.Threshold < 2 {
		return nil, barrierValidationError(ErrBarrierThresholdInvalid)
	}
	if params.Total < params.Threshold {
		return nil, barrierValidationError(ErrBarrierTotalInvalid)
	}
	result, err := svc.BarrierGenerateRecoveryKeys(ctx, &transport.BarrierGenerateRecoveryKeysRequest{Threshold: params.Threshold, Total: params.Total})
	if err != nil {
		return nil, mapBarrierError(err, "barrier generate recovery keys")
	}
	return map[string]interface{}{
		"success":      true,
		"threshold":    result.Threshold,
		"total_shares": result.TotalShares,
		"share_count":  result.ShareCount,
	}, nil
}

// handleBarrierEnableEncryption handles the barrier.enableEncryption method. It
// migrates a previously-unencrypted barrier to a keyed strategy in place. The
// migration runs asynchronously; the response acknowledges the start and
// clients poll barrier.status for completion. The target barrier is named in
// the request, and the service binds it to the caller's tenant.
func (s *Server) handleBarrierEnableEncryption(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc, err := s.barrierService()
	if err != nil {
		return nil, err
	}
	var params transport.BarrierEnableEncryptionRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	resp, err := svc.BarrierEnableEncryption(ctx, &params)
	if err != nil {
		return nil, mapBarrierError(err, "barrier enable encryption")
	}
	return resp, nil
}

// handleBarrierRecoverWithKeys handles the barrier.recoverWithKeys method.
// It recovers the barrier using recovery key shares.
func (s *Server) handleBarrierRecoverWithKeys(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc, err := s.barrierService()
	if err != nil {
		return nil, err
	}
	var params BarrierRecoverWithKeysParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	if len(params.Keys) == 0 {
		return nil, barrierValidationError(ErrBarrierRecoveryKeysRequired)
	}
	if err := svc.BarrierRecoverWithKeys(ctx, &transport.BarrierRecoverWithKeysRequest{Keys: params.Keys}); err != nil {
		return nil, mapBarrierError(err, "barrier recover with keys")
	}
	return map[string]interface{}{
		"success": true,
		"message": "barrier recovered with recovery keys",
	}, nil
}

// handleBarrierDeleteRecoveryKeys handles the barrier.deleteRecoveryKeys method.
// It deletes recovery key metadata from storage.
func (s *Server) handleBarrierDeleteRecoveryKeys(ctx context.Context, _ *JSONRPCRequest) (interface{}, error) {
	svc, err := s.barrierService()
	if err != nil {
		return nil, err
	}
	if err := svc.BarrierDeleteRecoveryKeys(ctx); err != nil {
		return nil, mapBarrierError(err, "barrier delete recovery keys")
	}
	return map[string]interface{}{
		"success": true,
		"message": "recovery keys deleted",
	}, nil
}

// handleBarrierHasRecoveryKeys handles the barrier.hasRecoveryKeys method. It
// reports whether recovery keys have been provisioned for the barrier, matching
// the gRPC/unix transport's BarrierHasRecoveryKeys RPC so MCP clients reach the
// same capability.
func (s *Server) handleBarrierHasRecoveryKeys(ctx context.Context, _ *JSONRPCRequest) (interface{}, error) {
	svc, err := s.barrierService()
	if err != nil {
		return nil, err
	}
	resp, err := svc.BarrierHasRecoveryKeys(ctx)
	if err != nil {
		return nil, mapBarrierError(err, "barrier has recovery keys")
	}
	return map[string]interface{}{
		"has_keys": resp.HasKeys,
	}, nil
}

// handleBarrierGenerateRootToken handles the barrier.generateRootToken method.
// It generates a one-time root token by proving knowledge of the master key
// through Shamir share reconstruction.
func (s *Server) handleBarrierGenerateRootToken(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc, err := s.barrierService()
	if err != nil {
		return nil, err
	}
	var params BarrierGenerateRootTokenParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	if len(params.Shares) == 0 {
		return nil, barrierValidationError(ErrBarrierSharesRequired)
	}
	token, err := svc.BarrierGenerateRootToken(ctx, &transport.BarrierGenerateRootTokenRequest{Shares: params.Shares})
	if err != nil {
		return nil, mapBarrierError(err, "barrier generate root token")
	}
	return map[string]interface{}{
		"success":    true,
		"token":      token.Token,
		"created_at": token.CreatedAt,
	}, nil
}
