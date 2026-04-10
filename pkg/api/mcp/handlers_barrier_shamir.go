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
	"encoding/json"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/seal"
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

// BarrierShamirDeleteShareParams represents parameters for deleting a single share.
type BarrierShamirDeleteShareParams struct {
	Index int `json:"index"`
}

// BarrierGenerateRootTokenParams represents parameters for root token generation.
type BarrierGenerateRootTokenParams struct {
	Shares []string `json:"shares"`
}

// handleBarrierInitialize handles the barrier.initialize method.
// It initializes the barrier with a secret-based sealing strategy.
func (s *Server) handleBarrierInitialize(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if s.barrier == nil {
		return nil, ErrBarrierNotConfigured
	}

	var params BarrierInitializeParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if params.Secret == "" {
		return nil, ErrBarrierSecretRequired
	}

	creds := seal.Credentials{Secret: params.Secret}
	if err := s.barrier.Initialize(ctx, creds); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success": true,
		"message": "barrier initialized",
	}, nil
}

// handleBarrierInitializeShamir handles the barrier.initializeShamir method.
// It initializes the barrier with Shamir secret sharing and returns the generated shares.
func (s *Server) handleBarrierInitializeShamir(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if s.barrier == nil {
		return nil, ErrBarrierNotConfigured
	}

	var params BarrierInitializeShamirParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	creds := seal.Credentials{Secret: params.Secret}
	result, err := s.barrier.InitializeShamir(ctx, creds)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success":      true,
		"shares":       result.Shares,
		"threshold":    result.Threshold,
		"total_shares": result.TotalShares,
	}, nil
}

// handleBarrierUnseal handles the barrier.unseal method.
// It unseals the barrier using a secret credential.
func (s *Server) handleBarrierUnseal(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if s.barrier == nil {
		return nil, ErrBarrierNotConfigured
	}

	var params BarrierUnsealParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if params.Secret == "" {
		return nil, ErrBarrierSecretRequired
	}

	creds := seal.Credentials{Secret: params.Secret}
	if err := s.barrier.Unseal(ctx, creds); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success": true,
		"message": "barrier unsealed",
	}, nil
}

// handleBarrierUnsealShare handles the barrier.unsealShare method.
// It submits a single Shamir share for quorum-based unsealing.
func (s *Server) handleBarrierUnsealShare(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if s.barrier == nil {
		return nil, ErrBarrierNotConfigured
	}

	var params BarrierUnsealShareParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if params.Share == "" {
		return nil, ErrBarrierShareRequired
	}

	progress, err := s.barrier.UnsealWithShare(ctx, params.Share)
	if err != nil {
		return nil, err
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
	if s.barrier == nil {
		return nil, ErrBarrierNotConfigured
	}

	var params BarrierUnsealSharesParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if len(params.Shares) == 0 {
		return nil, ErrBarrierSharesRequired
	}

	if err := s.barrier.UnsealWithShares(ctx, params.Shares); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success": true,
		"message": "barrier unsealed with shares",
	}, nil
}

// handleBarrierSeal handles the barrier.seal method.
// It transitions the barrier to sealed state.
func (s *Server) handleBarrierSeal(req *JSONRPCRequest) (interface{}, error) {
	if s.barrier == nil {
		return nil, ErrBarrierNotConfigured
	}

	if err := s.barrier.Seal(); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success": true,
		"message": "barrier sealed",
	}, nil
}

// handleBarrierStatus handles the barrier.status method.
// It returns the current barrier status.
func (s *Server) handleBarrierStatus(req *JSONRPCRequest) (interface{}, error) {
	if s.barrier == nil {
		return nil, ErrBarrierNotConfigured
	}

	status := s.barrier.Status()
	return map[string]interface{}{
		"sealed":          status.Sealed,
		"strategy":        string(status.Strategy),
		"hardware_backed": status.HardwareBacked,
	}, nil
}

// handleBarrierRekey handles the barrier.rekey method.
// It generates new Shamir shares with a new threshold and total.
func (s *Server) handleBarrierRekey(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if s.barrier == nil {
		return nil, ErrBarrierNotConfigured
	}

	var params BarrierRekeyParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if params.Threshold < 2 {
		return nil, ErrBarrierThresholdInvalid
	}

	if params.Total < params.Threshold {
		return nil, ErrBarrierTotalInvalid
	}

	result, err := s.barrier.Rekey(ctx, params.Threshold, params.Total)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success":      true,
		"shares":       result.Shares,
		"threshold":    result.Threshold,
		"total_shares": result.TotalShares,
	}, nil
}

// handleBarrierShamirListShares handles the barrier.shamirListShares method.
// It returns information about the shares stored in the Shamir strategy.
func (s *Server) handleBarrierShamirListShares(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if s.barrier == nil {
		return nil, ErrBarrierNotConfigured
	}

	shamirStrat := s.barrier.ShamirStrategy()
	if shamirStrat == nil {
		return nil, ErrBarrierShamirNotConfigured
	}

	count, err := shamirStrat.ShareCount(ctx)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"count":     count,
		"threshold": shamirStrat.Threshold(),
		"total":     shamirStrat.TotalShares(),
	}, nil
}

// handleBarrierShamirDeleteShare handles the barrier.shamirDeleteShare method.
// It deletes a single share by index from the Shamir strategy storage.
func (s *Server) handleBarrierShamirDeleteShare(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if s.barrier == nil {
		return nil, ErrBarrierNotConfigured
	}

	shamirStrat := s.barrier.ShamirStrategy()
	if shamirStrat == nil {
		return nil, ErrBarrierShamirNotConfigured
	}

	var params BarrierShamirDeleteShareParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if params.Index < 1 {
		return nil, ErrBarrierShareIndexInvalid
	}

	if err := shamirStrat.DeleteShare(ctx, params.Index); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("share %d deleted", params.Index),
	}, nil
}

// handleBarrierShamirDeleteAllShares handles the barrier.shamirDeleteAllShares method.
// It deletes all shares from the Shamir strategy storage.
func (s *Server) handleBarrierShamirDeleteAllShares(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if s.barrier == nil {
		return nil, ErrBarrierNotConfigured
	}

	shamirStrat := s.barrier.ShamirStrategy()
	if shamirStrat == nil {
		return nil, ErrBarrierShamirNotConfigured
	}

	if err := shamirStrat.DeleteAllShares(ctx); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success": true,
		"message": "all shares deleted",
	}, nil
}

// handleBarrierShamirVerify handles the barrier.shamirVerify method.
// It verifies the integrity and consistency of all stored shares.
func (s *Server) handleBarrierShamirVerify(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if s.barrier == nil {
		return nil, ErrBarrierNotConfigured
	}

	shamirStrat := s.barrier.ShamirStrategy()
	if shamirStrat == nil {
		return nil, ErrBarrierShamirNotConfigured
	}

	if err := shamirStrat.VerifyShares(ctx); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success": true,
		"message": "shares verified successfully",
	}, nil
}

// handleBarrierGenerateRecoveryKeys handles the barrier.generateRecoveryKeys method.
// It generates a set of recovery key shares for disaster recovery.
func (s *Server) handleBarrierGenerateRecoveryKeys(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if s.barrier == nil {
		return nil, ErrBarrierNotConfigured
	}

	var params BarrierGenerateRecoveryKeysParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if params.Threshold < 2 {
		return nil, ErrBarrierThresholdInvalid
	}

	if params.Total < params.Threshold {
		return nil, ErrBarrierTotalInvalid
	}

	result, err := s.barrier.GenerateRecoveryKeys(ctx, params.Threshold, params.Total)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success":      true,
		"shares":       result.Shares,
		"threshold":    result.Threshold,
		"total_shares": result.TotalShares,
	}, nil
}

// handleBarrierRecoverWithKeys handles the barrier.recoverWithKeys method.
// It recovers the barrier using recovery key shares.
func (s *Server) handleBarrierRecoverWithKeys(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if s.barrier == nil {
		return nil, ErrBarrierNotConfigured
	}

	var params BarrierRecoverWithKeysParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if len(params.Keys) == 0 {
		return nil, ErrBarrierRecoveryKeysRequired
	}

	if err := s.barrier.RecoverWithKeys(ctx, params.Keys); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success": true,
		"message": "barrier recovered with recovery keys",
	}, nil
}

// handleBarrierDeleteRecoveryKeys handles the barrier.deleteRecoveryKeys method.
// It deletes recovery key metadata from storage.
func (s *Server) handleBarrierDeleteRecoveryKeys(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if s.barrier == nil {
		return nil, ErrBarrierNotConfigured
	}

	if err := s.barrier.DeleteRecoveryKeys(ctx); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success": true,
		"message": "recovery keys deleted",
	}, nil
}

// handleBarrierGenerateRootToken handles the barrier.generateRootToken method.
// It generates a one-time root token by proving knowledge of the master key
// through Shamir share reconstruction.
func (s *Server) handleBarrierGenerateRootToken(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if s.barrier == nil {
		return nil, ErrBarrierNotConfigured
	}

	var params BarrierGenerateRootTokenParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if len(params.Shares) == 0 {
		return nil, ErrBarrierSharesRequired
	}

	token, err := s.barrier.GenerateRootToken(ctx, params.Shares)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success":    true,
		"token":      token.Token,
		"created_at": token.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}, nil
}
