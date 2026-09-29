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
	"errors"
	"fmt"
	"log/slog"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// BarrierMode identifies where the barrier the admin plane operates lives.
type BarrierMode string

// BarrierModeEmbedded is the only mode the admin plane reports: it operates
// the system barrier through the in-process XKMSService (SystemBarrier) and
// holds no barrier client of its own. The field stays on the status response
// because the admin SPA keys its sealed-barrier redirect on it.
const BarrierModeEmbedded BarrierMode = "embedded"

// BarrierNotEnabledError is returned when a barrier operation is attempted
// but the server has no system barrier configured.
type BarrierNotEnabledError struct {
	Operation string
}

// Error implements the error interface.
func (e *BarrierNotEnabledError) Error() string {
	return fmt.Sprintf("admin: barrier %q not available — barrier not enabled", e.Operation)
}

// BarrierNotInitializedError is returned when an operation needs an
// initialized barrier and the barrier has not been initialized.
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
	// Status returns the current barrier state.
	Status(ctx context.Context) (*BarrierStatusResponse, error)
	// Initialize initializes the barrier with a passphrase.
	Initialize(ctx context.Context, req *BarrierInitializeRequest) error
	// Seal seals the barrier.
	Seal(ctx context.Context) error
	// Unseal unseals the barrier with a passphrase.
	Unseal(ctx context.Context, req *BarrierUnsealRequest) error
	// InitializeShamir initializes with Shamir secret sharing.
	InitializeShamir(ctx context.Context, req *BarrierInitializeShamirRequest) (*BarrierInitializeShamirResponse, error)
	// UnsealWithShare submits a single Shamir share.
	UnsealWithShare(ctx context.Context, req *BarrierUnsealShareRequest) (*BarrierUnsealShareResponse, error)
	// Rekey generates new Shamir shares.
	Rekey(ctx context.Context, req *BarrierRekeyRequest) (*BarrierRekeyResponse, error)
	// GenerateRecoveryKeys generates disaster recovery keys.
	GenerateRecoveryKeys(ctx context.Context, req *BarrierGenerateRecoveryKeysRequest) (*BarrierRecoveryKeysResponse, error)
	// RecoverWithKeys recovers the barrier using recovery keys.
	RecoverWithKeys(ctx context.Context, req *BarrierRecoverWithKeysRequest) error
	// HasRecoveryKeys checks if recovery keys exist.
	HasRecoveryKeys(ctx context.Context) (bool, error)
	// GenerateRootToken generates a root token from Shamir shares.
	GenerateRootToken(ctx context.Context, req *BarrierGenerateRootTokenRequest) (*BarrierRootTokenResponse, error)
}

// SystemBarrier is the system-barrier surface of the XKMSService the admin
// plane operates the barrier through. Every method is platform-scoped by the
// XKMSService itself (requirePlatformScope, go-xkms#1227): a tenant-scoped
// caller is refused before the barrier is touched. The admin plane holds no
// barrier handle of its own, so it cannot bypass that check (go-xkms#1244).
type SystemBarrier interface {
	BarrierStatus(ctx context.Context) (*transport.BarrierStatusResponse, error)
	BarrierInitialize(ctx context.Context, req *transport.BarrierInitializeRequest) error
	BarrierSeal(ctx context.Context) error
	BarrierUnseal(ctx context.Context, req *transport.BarrierUnsealRequest) error
	BarrierInitializeShamir(ctx context.Context, req *transport.BarrierInitializeShamirRequest) (*transport.BarrierInitializeShamirResponse, error)
	BarrierUnsealWithShare(ctx context.Context, req *transport.BarrierUnsealShareRequest) (*transport.BarrierUnsealShareResponse, error)
	BarrierRekey(ctx context.Context, req *transport.BarrierRekeyRequest) (*transport.BarrierRekeyResponse, error)
	BarrierGenerateRecoveryKeys(ctx context.Context, req *transport.BarrierGenerateRecoveryKeysRequest) (*transport.BarrierRecoveryKeysResponse, error)
	BarrierRecoverWithKeys(ctx context.Context, req *transport.BarrierRecoverWithKeysRequest) error
	BarrierHasRecoveryKeys(ctx context.Context) (*transport.BarrierHasRecoveryKeysResponse, error)
	BarrierGenerateRootToken(ctx context.Context, req *transport.BarrierGenerateRootTokenRequest) (*transport.BarrierRootTokenResponse, error)
}

// Compile-time checks: the XKMSService is the SystemBarrier, and
// barrierService is the BarrierService.
var (
	_ SystemBarrier  = (*xkms.XKMSService)(nil)
	_ BarrierService = (*barrierService)(nil)
)

type barrierService struct {
	barrier SystemBarrier
	logger  *slog.Logger
}

// NewBarrierService returns the admin plane's BarrierService over the
// XKMSService's system barrier.
func NewBarrierService(barrier SystemBarrier, logger *slog.Logger) BarrierService {
	return &barrierService{
		barrier: barrier,
		logger:  logger,
	}
}

// translateBarrierError maps an XKMSService barrier error onto the admin
// plane's error vocabulary:
//
//   - the platform-scope refusal (*xkms.TenantBindingError) becomes a
//     *PlatformScopeError, the admin plane's refusal for platform-only
//     operations, which every admin route answers exactly as it answers a
//     caller that lacks the permission (writePermissionDenied);
//   - xkms.ErrNotConfigured (no system barrier) becomes a
//     *BarrierNotEnabledError;
//   - seal.ErrNotInitialized becomes a *BarrierNotInitializedError;
//   - anything else is wrapped in a *BarrierError.
func translateBarrierError(operation string, err error) error {
	var bindErr *xkms.TenantBindingError
	if errors.As(err, &bindErr) {
		return &PlatformScopeError{Op: "barrier " + operation, CallerTenantID: bindErr.CallerTenantID}
	}
	if errors.Is(err, xkms.ErrNotConfigured) {
		return &BarrierNotEnabledError{Operation: operation}
	}
	if errors.Is(err, seal.ErrNotInitialized) {
		return &BarrierNotInitializedError{}
	}
	return &BarrierError{Operation: operation, Err: err}
}

// Status returns the current barrier state. A server with no system barrier
// reports Enabled=false rather than an error; a tenant-scoped caller is
// refused like every other barrier operation.
func (s *barrierService) Status(ctx context.Context) (*BarrierStatusResponse, error) {
	resp, err := s.barrier.BarrierStatus(ctx)
	if err != nil {
		// The XKMSService checks the caller's scope before it looks for a
		// barrier, so a tenant-scoped caller never learns whether one exists.
		if errors.Is(err, xkms.ErrNotConfigured) {
			return &BarrierStatusResponse{Mode: BarrierModeEmbedded}, nil
		}
		return nil, translateBarrierError("status", err)
	}
	return &BarrierStatusResponse{
		Mode:           BarrierModeEmbedded,
		Enabled:        true,
		Sealed:         resp.Sealed,
		Strategy:       resp.Strategy,
		HardwareBacked: resp.HardwareBacked,
		InitializedAt:  resp.InitializedAt,
	}, nil
}

// Initialize initializes the barrier with a passphrase.
func (s *barrierService) Initialize(ctx context.Context, req *BarrierInitializeRequest) error {
	if err := s.barrier.BarrierInitialize(ctx, &transport.BarrierInitializeRequest{Secret: req.Secret}); err != nil {
		return translateBarrierError("initialize", err)
	}
	s.logger.Info("barrier initialized")
	return nil
}

// Seal seals the barrier, preventing further data access.
func (s *barrierService) Seal(ctx context.Context) error {
	if err := s.barrier.BarrierSeal(ctx); err != nil {
		return translateBarrierError("seal", err)
	}
	s.logger.Info("barrier sealed")
	return nil
}

// Unseal unseals the barrier with a passphrase.
func (s *barrierService) Unseal(ctx context.Context, req *BarrierUnsealRequest) error {
	if err := s.barrier.BarrierUnseal(ctx, &transport.BarrierUnsealRequest{Secret: req.Secret}); err != nil {
		return translateBarrierError("unseal", err)
	}
	s.logger.Info("barrier unsealed")
	return nil
}

// InitializeShamir initializes the barrier with Shamir secret sharing.
func (s *barrierService) InitializeShamir(ctx context.Context, req *BarrierInitializeShamirRequest) (*BarrierInitializeShamirResponse, error) {
	resp, err := s.barrier.BarrierInitializeShamir(ctx, &transport.BarrierInitializeShamirRequest{
		Secret:      req.Secret,
		Threshold:   req.Threshold,
		TotalShares: req.TotalShares,
	})
	if err != nil {
		return nil, translateBarrierError("initialize-shamir", err)
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
	resp, err := s.barrier.BarrierUnsealWithShare(ctx, &transport.BarrierUnsealShareRequest{Share: req.Share})
	if err != nil {
		return nil, translateBarrierError("unseal-share", err)
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
	resp, err := s.barrier.BarrierRekey(ctx, &transport.BarrierRekeyRequest{
		Threshold: req.Threshold,
		Total:     req.Total,
	})
	if err != nil {
		return nil, translateBarrierError("rekey", err)
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
	resp, err := s.barrier.BarrierGenerateRecoveryKeys(ctx, &transport.BarrierGenerateRecoveryKeysRequest{
		Threshold: req.Threshold,
		Total:     req.Total,
	})
	if err != nil {
		return nil, translateBarrierError("generate-recovery-keys", err)
	}
	s.logger.Info("barrier recovery keys generated",
		slog.Int("threshold", resp.Threshold),
		slog.Int("total", resp.TotalShares))
	return &BarrierRecoveryKeysResponse{
		Threshold:  resp.Threshold,
		Total:      resp.TotalShares,
		ShareCount: resp.ShareCount,
	}, nil
}

// RecoverWithKeys recovers the barrier using recovery keys.
func (s *barrierService) RecoverWithKeys(ctx context.Context, req *BarrierRecoverWithKeysRequest) error {
	if err := s.barrier.BarrierRecoverWithKeys(ctx, &transport.BarrierRecoverWithKeysRequest{Keys: req.Keys}); err != nil {
		return translateBarrierError("recover-with-keys", err)
	}
	s.logger.Info("barrier recovered with keys")
	return nil
}

// HasRecoveryKeys checks if recovery keys exist.
func (s *barrierService) HasRecoveryKeys(ctx context.Context) (bool, error) {
	resp, err := s.barrier.BarrierHasRecoveryKeys(ctx)
	if err != nil {
		return false, translateBarrierError("has-recovery-keys", err)
	}
	return resp.HasKeys, nil
}

// GenerateRootToken generates a root token from Shamir shares.
func (s *barrierService) GenerateRootToken(ctx context.Context, req *BarrierGenerateRootTokenRequest) (*BarrierRootTokenResponse, error) {
	resp, err := s.barrier.BarrierGenerateRootToken(ctx, &transport.BarrierGenerateRootTokenRequest{Shares: req.Shares})
	if err != nil {
		return nil, translateBarrierError("generate-root-token", err)
	}
	s.logger.Info("barrier root token generated")
	return &BarrierRootTokenResponse{
		Token:     resp.Token,
		CreatedAt: resp.CreatedAt,
	}, nil
}
