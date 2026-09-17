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

package admin

import (
	"context"
	"fmt"
	"log/slog"

	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// BarrierMode identifies whether the barrier is managed locally or by a remote QRDB server.
type BarrierMode string

const (
	// BarrierModeEmbedded indicates the barrier is managed locally by an embedded QRDB instance.
	BarrierModeEmbedded BarrierMode = "embedded"
	// BarrierModeRemote indicates the barrier is managed by a remote QRDB server.
	BarrierModeRemote BarrierMode = "remote"
)

// BarrierRemoteModeError is returned when a mutating barrier operation is
// attempted in remote mode.
type BarrierRemoteModeError struct {
	Operation string
}

// Error implements the error interface.
func (e *BarrierRemoteModeError) Error() string {
	return fmt.Sprintf("admin: barrier operation %q not available in remote mode", e.Operation)
}

// BarrierNotInitializedError is returned when the barrier has not been initialized.
type BarrierNotInitializedError struct{}

// Error implements the error interface.
func (e *BarrierNotInitializedError) Error() string {
	return "admin: barrier not initialized"
}

// BarrierError wraps an underlying barrier error with context.
type BarrierError struct {
	Operation string
	Err       error
}

// Error implements the error interface.
func (e *BarrierError) Error() string {
	return fmt.Sprintf("admin: barrier %s: %v", e.Operation, e.Err)
}

// Unwrap returns the underlying error.
func (e *BarrierError) Unwrap() error {
	return e.Err
}

// BarrierStatusResponse represents the barrier status returned by the admin API.
type BarrierStatusResponse struct {
	Mode           BarrierMode `json:"mode"`
	Enabled        bool        `json:"enabled"`
	Sealed         bool        `json:"sealed"`
	Strategy       string      `json:"strategy"`
	HardwareBacked bool        `json:"hardware_backed"`
	InitializedAt  string      `json:"initialized_at,omitempty"`
}

// BarrierInitializeRequest represents a request to initialize the barrier.
type BarrierInitializeRequest struct {
	Secret string `json:"secret"`
}

// BarrierUnsealRequest represents a request to unseal the barrier.
type BarrierUnsealRequest struct {
	Secret string `json:"secret"`
}

// BarrierInitializeShamirRequest represents a request to initialize the barrier with Shamir secret sharing.
type BarrierInitializeShamirRequest struct {
	Secret      string `json:"secret"`
	Threshold   int    `json:"threshold"`
	TotalShares int    `json:"total_shares"`
}

// BarrierInitializeShamirResponse represents the response from Shamir
// initialization. Share material is never returned (qrdb share-free
// contract): shares are sealed to enrolled Security Officers; only the
// threshold/total metadata is reported.
type BarrierInitializeShamirResponse struct {
	Threshold   int `json:"threshold"`
	TotalShares int `json:"total_shares"`
	ShareCount  int `json:"share_count"`
}

// BarrierUnsealShareRequest represents a request to submit a single Shamir share.
type BarrierUnsealShareRequest struct {
	Share string `json:"share"`
}

// BarrierUnsealShareResponse represents the progress toward the unseal threshold.
type BarrierUnsealShareResponse struct {
	Required  int  `json:"required"`
	Submitted int  `json:"submitted"`
	Complete  bool `json:"complete"`
}

// BarrierRekeyRequest represents a request to rekey the barrier Shamir shares.
type BarrierRekeyRequest struct {
	Threshold int `json:"threshold"`
	Total     int `json:"total"`
}

// BarrierRekeyResponse represents the response from a rekey operation.
// New shares are sealed to enrolled Security Officers and never returned
// (qrdb share-free contract); only the threshold/total metadata is reported.
type BarrierRekeyResponse struct {
	Threshold   int `json:"threshold"`
	TotalShares int `json:"total_shares"`
	ShareCount  int `json:"share_count"`
}

// BarrierGenerateRecoveryKeysRequest represents a request to generate recovery keys.
type BarrierGenerateRecoveryKeysRequest struct {
	Threshold int `json:"threshold"`
	Total     int `json:"total"`
}

// BarrierRecoveryKeysResponse represents the response from generating
// recovery keys. Recovery shares are sealed to enrolled recovery officers
// and never returned (qrdb share-free contract); only the threshold/total
// metadata is reported.
type BarrierRecoveryKeysResponse struct {
	Threshold  int `json:"threshold"`
	Total      int `json:"total"`
	ShareCount int `json:"share_count"`
}

// BarrierRecoverWithKeysRequest represents a request to recover the barrier using recovery keys.
type BarrierRecoverWithKeysRequest struct {
	Keys []string `json:"keys"`
}

// BarrierGenerateRootTokenRequest represents a request to generate a root token.
type BarrierGenerateRootTokenRequest struct {
	Shares []string `json:"shares"`
}

// BarrierRootTokenResponse represents the response from generating a root token.
type BarrierRootTokenResponse struct {
	Token     string `json:"token"`
	CreatedAt string `json:"created_at"`
}

// BarrierService defines the interface for barrier management operations.
type BarrierService interface {
	// Status returns the current barrier state and mode.
	Status(ctx context.Context) (*BarrierStatusResponse, error)
	// Initialize initializes the barrier with a passphrase (embedded only).
	Initialize(ctx context.Context, req *BarrierInitializeRequest) error
	// Seal seals the barrier (embedded only).
	Seal(ctx context.Context) error
	// Unseal unseals the barrier with a passphrase (embedded only).
	Unseal(ctx context.Context, req *BarrierUnsealRequest) error
	// InitializeShamir initializes with Shamir secret sharing (embedded only).
	InitializeShamir(ctx context.Context, req *BarrierInitializeShamirRequest) (*BarrierInitializeShamirResponse, error)
	// UnsealWithShare submits a single Shamir share (embedded only).
	UnsealWithShare(ctx context.Context, req *BarrierUnsealShareRequest) (*BarrierUnsealShareResponse, error)
	// Rekey generates new Shamir shares (embedded only).
	Rekey(ctx context.Context, req *BarrierRekeyRequest) (*BarrierRekeyResponse, error)
	// GenerateRecoveryKeys generates disaster recovery keys (embedded only).
	GenerateRecoveryKeys(ctx context.Context, req *BarrierGenerateRecoveryKeysRequest) (*BarrierRecoveryKeysResponse, error)
	// RecoverWithKeys recovers the barrier using recovery keys (embedded only).
	RecoverWithKeys(ctx context.Context, req *BarrierRecoverWithKeysRequest) error
	// HasRecoveryKeys checks if recovery keys exist (embedded only).
	HasRecoveryKeys(ctx context.Context) (bool, error)
	// GenerateRootToken generates a root token from Shamir shares (embedded only).
	GenerateRootToken(ctx context.Context, req *BarrierGenerateRootTokenRequest) (*BarrierRootTokenResponse, error)
}

// Ensure barrierService implements BarrierService at compile time.
var _ BarrierService = (*barrierService)(nil)

type barrierService struct {
	mode    BarrierMode
	barrier db.BarrierClient
	logger  *slog.Logger
}

// NewBarrierService creates a new barrier service instance.
func NewBarrierService(mode BarrierMode, barrier db.BarrierClient, logger *slog.Logger) BarrierService {
	return &barrierService{
		mode:    mode,
		barrier: barrier,
		logger:  logger,
	}
}

// BarrierNotEnabledError is returned when a barrier operation is attempted
// but the barrier is not configured.
type BarrierNotEnabledError struct {
	Operation string
}

// Error implements the error interface.
func (e *BarrierNotEnabledError) Error() string {
	return fmt.Sprintf("admin: barrier %q not available — barrier not enabled", e.Operation)
}

// requireEmbedded returns a BarrierRemoteModeError if the barrier is in remote mode.
func (s *barrierService) requireEmbedded(operation string) error {
	if s.barrier == nil {
		return &BarrierNotEnabledError{Operation: operation}
	}
	if s.mode == BarrierModeRemote {
		return &BarrierRemoteModeError{Operation: operation}
	}
	return nil
}

// Status returns the current barrier state and mode. When the barrier is not
// configured (nil client), it returns a response indicating the barrier is
// disabled rather than returning an error.
func (s *barrierService) Status(ctx context.Context) (*BarrierStatusResponse, error) {
	if s.barrier == nil {
		return &BarrierStatusResponse{
			Mode:    s.mode,
			Enabled: false,
			Sealed:  false,
		}, nil
	}

	resp, err := s.barrier.BarrierStatus(ctx)
	if err != nil {
		return nil, &BarrierError{Operation: "status", Err: err}
	}
	return &BarrierStatusResponse{
		Enabled:        true,
		Mode:           s.mode,
		Sealed:         resp.Sealed,
		Strategy:       resp.Strategy,
		HardwareBacked: resp.HardwareBacked,
		InitializedAt:  resp.InitializedAt,
	}, nil
}

// Initialize initializes the barrier with a passphrase.
func (s *barrierService) Initialize(ctx context.Context, req *BarrierInitializeRequest) error {
	if err := s.requireEmbedded("initialize"); err != nil {
		return err
	}
	if err := s.barrier.BarrierInitialize(ctx, &db.BarrierInitializeRequest{
		Secret: []byte(req.Secret),
	}); err != nil {
		return &BarrierError{Operation: "initialize", Err: err}
	}
	s.logger.Info("barrier initialized")
	return nil
}

// Seal seals the barrier, preventing further data access.
func (s *barrierService) Seal(ctx context.Context) error {
	if err := s.requireEmbedded("seal"); err != nil {
		return err
	}
	if err := s.barrier.BarrierSeal(ctx); err != nil {
		return &BarrierError{Operation: "seal", Err: err}
	}
	s.logger.Info("barrier sealed")
	return nil
}

// Unseal unseals the barrier with a passphrase.
func (s *barrierService) Unseal(ctx context.Context, req *BarrierUnsealRequest) error {
	if err := s.requireEmbedded("unseal"); err != nil {
		return err
	}
	if err := s.barrier.BarrierUnseal(ctx, &db.BarrierUnsealRequest{
		Secret: []byte(req.Secret),
	}); err != nil {
		return &BarrierError{Operation: "unseal", Err: err}
	}
	s.logger.Info("barrier unsealed")
	return nil
}

// InitializeShamir initializes the barrier with Shamir secret sharing.
func (s *barrierService) InitializeShamir(ctx context.Context, req *BarrierInitializeShamirRequest) (*BarrierInitializeShamirResponse, error) {
	if err := s.requireEmbedded("initialize-shamir"); err != nil {
		return nil, err
	}
	resp, err := s.barrier.BarrierInitializeShamir(ctx, &db.BarrierInitializeShamirRequest{
		Secret:      []byte(req.Secret),
		Threshold:   req.Threshold,
		TotalShares: req.TotalShares,
	})
	if err != nil {
		return nil, &BarrierError{Operation: "initialize-shamir", Err: err}
	}
	s.logger.Info("barrier initialized with shamir",
		slog.Int("threshold", resp.Threshold),
		slog.Int("total_shares", resp.TotalShares))
	return &BarrierInitializeShamirResponse{
		Threshold:   resp.Threshold,
		TotalShares: resp.TotalShares,
		ShareCount:  resp.ShareCount,
	}, nil
}

// UnsealWithShare submits a single Shamir share toward the unseal threshold.
func (s *barrierService) UnsealWithShare(ctx context.Context, req *BarrierUnsealShareRequest) (*BarrierUnsealShareResponse, error) {
	if err := s.requireEmbedded("unseal-share"); err != nil {
		return nil, err
	}
	resp, err := s.barrier.BarrierUnsealWithShare(ctx, &db.BarrierUnsealShareRequest{
		Share: req.Share,
	})
	if err != nil {
		return nil, &BarrierError{Operation: "unseal-share", Err: err}
	}
	s.logger.Info("barrier unseal share submitted",
		slog.Int("submitted", resp.Submitted),
		slog.Int("required", resp.Required),
		slog.Bool("complete", resp.Complete))
	return &BarrierUnsealShareResponse{
		Required:  resp.Required,
		Submitted: resp.Submitted,
		Complete:  resp.Complete,
	}, nil
}

// Rekey generates new Shamir shares with the specified threshold and total count.
func (s *barrierService) Rekey(ctx context.Context, req *BarrierRekeyRequest) (*BarrierRekeyResponse, error) {
	if err := s.requireEmbedded("rekey"); err != nil {
		return nil, err
	}
	resp, err := s.barrier.BarrierRekey(ctx, &db.BarrierRekeyRequest{
		Threshold: req.Threshold,
		Total:     req.Total,
	})
	if err != nil {
		return nil, &BarrierError{Operation: "rekey", Err: err}
	}
	s.logger.Info("barrier rekeyed",
		slog.Int("threshold", resp.Threshold),
		slog.Int("total_shares", resp.TotalShares))
	return &BarrierRekeyResponse{
		Threshold:   resp.Threshold,
		TotalShares: resp.TotalShares,
		ShareCount:  resp.ShareCount,
	}, nil
}

// GenerateRecoveryKeys generates disaster recovery keys.
func (s *barrierService) GenerateRecoveryKeys(ctx context.Context, req *BarrierGenerateRecoveryKeysRequest) (*BarrierRecoveryKeysResponse, error) {
	if err := s.requireEmbedded("generate-recovery-keys"); err != nil {
		return nil, err
	}
	resp, err := s.barrier.BarrierGenerateRecoveryKeys(ctx, &db.BarrierGenerateRecoveryKeysRequest{
		Threshold: req.Threshold,
		Total:     req.Total,
	})
	if err != nil {
		return nil, &BarrierError{Operation: "generate-recovery-keys", Err: err}
	}
	s.logger.Info("barrier recovery keys generated",
		slog.Int("threshold", resp.Threshold),
		slog.Int("total", resp.Total))
	return &BarrierRecoveryKeysResponse{
		Threshold:  resp.Threshold,
		Total:      resp.Total,
		ShareCount: resp.ShareCount,
	}, nil
}

// RecoverWithKeys recovers the barrier using recovery keys.
func (s *barrierService) RecoverWithKeys(ctx context.Context, req *BarrierRecoverWithKeysRequest) error {
	if err := s.requireEmbedded("recover-with-keys"); err != nil {
		return err
	}
	if err := s.barrier.BarrierRecoverWithKeys(ctx, &db.BarrierRecoverWithKeysRequest{
		Keys: req.Keys,
	}); err != nil {
		return &BarrierError{Operation: "recover-with-keys", Err: err}
	}
	s.logger.Info("barrier recovered with keys")
	return nil
}

// HasRecoveryKeys checks if recovery keys exist.
func (s *barrierService) HasRecoveryKeys(ctx context.Context) (bool, error) {
	if err := s.requireEmbedded("has-recovery-keys"); err != nil {
		return false, err
	}
	resp, err := s.barrier.BarrierHasRecoveryKeys(ctx)
	if err != nil {
		return false, &BarrierError{Operation: "has-recovery-keys", Err: err}
	}
	return resp.HasKeys, nil
}

// GenerateRootToken generates a root token from Shamir shares.
func (s *barrierService) GenerateRootToken(ctx context.Context, req *BarrierGenerateRootTokenRequest) (*BarrierRootTokenResponse, error) {
	if err := s.requireEmbedded("generate-root-token"); err != nil {
		return nil, err
	}
	resp, err := s.barrier.BarrierGenerateRootToken(ctx, &db.BarrierGenerateRootTokenRequest{
		Shares: req.Shares,
	})
	if err != nil {
		return nil, &BarrierError{Operation: "generate-root-token", Err: err}
	}
	s.logger.Info("barrier root token generated")
	return &BarrierRootTokenResponse{
		Token:     resp.Token,
		CreatedAt: resp.CreatedAt,
	}, nil
}
