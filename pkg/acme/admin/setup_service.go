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
	"encoding/json"
	"fmt"
	"log/slog"
	"sync/atomic"

	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
)

// SetupStatus represents the current initialization state.
type SetupStatus string

const (
	// SetupStatusPending indicates setup has not been completed.
	SetupStatusPending SetupStatus = "pending"
	// SetupStatusComplete indicates setup has been completed.
	SetupStatusComplete SetupStatus = "complete"
)

// SetupAlreadyCompleteError is returned when setup has already been completed.
type SetupAlreadyCompleteError struct{}

// Error implements the error interface.
func (e *SetupAlreadyCompleteError) Error() string {
	return "admin: setup already complete"
}

// SetupBarrierError wraps an underlying barrier error during setup.
type SetupBarrierError struct {
	Operation string
	Err       error
}

// Error implements the error interface.
func (e *SetupBarrierError) Error() string {
	return fmt.Sprintf("admin: setup barrier %s: %v", e.Operation, e.Err)
}

// Unwrap returns the underlying error.
func (e *SetupBarrierError) Unwrap() error {
	return e.Err
}

// SetupError represents a general setup error.
type SetupError struct {
	Message string
}

// Error implements the error interface.
func (e *SetupError) Error() string {
	return fmt.Sprintf("admin: setup: %s", e.Message)
}

// UnsupportedBarrierStrategyError is returned when an unknown barrier strategy is requested.
type UnsupportedBarrierStrategyError struct {
	Strategy string
}

// Error implements the error interface.
func (e *UnsupportedBarrierStrategyError) Error() string {
	return fmt.Sprintf("admin: setup: unsupported barrier strategy: %s", e.Strategy)
}

// SetupStatusResponse describes the current setup state.
type SetupStatusResponse struct {
	Status        SetupStatus `json:"status"`
	Mode          BarrierMode `json:"mode"`
	CAInitialized bool        `json:"ca_initialized"`
}

// SetupBarrierRequest configures the encryption barrier.
type SetupBarrierRequest struct {
	Strategy string             `json:"strategy"`
	Secret   string             `json:"secret"`
	Shamir   *SetupShamirConfig `json:"shamir,omitempty"`
}

// SetupShamirConfig holds Shamir secret sharing parameters.
type SetupShamirConfig struct {
	Threshold int `json:"threshold"`
	Total     int `json:"total"`
}

// SetupBarrierResponse is returned after barrier initialization.
//
// Share-free contract: the response carries Shamir metadata only. Shares are
// sealed to enrolled Security Officers via the ceremony distributor and are
// never returned over the wire.
type SetupBarrierResponse struct {
	Threshold  int `json:"threshold,omitempty"`
	Total      int `json:"total,omitempty"`
	ShareCount int `json:"share_count,omitempty"`
}

// SetupCARequest configures the Certificate Authority.
type SetupCARequest struct {
	RootCAName         string `json:"root_ca_name"`
	IntermediateCAName string `json:"intermediate_ca_name"`
	KeyAlgorithm       string `json:"key_algorithm"`
	ValidityYears      int    `json:"validity_years"`
	Organization       string `json:"organization,omitempty"`
	OrganizationalUnit string `json:"organizational_unit,omitempty"`
	Country            string `json:"country,omitempty"`
	State              string `json:"state,omitempty"`
	Locality           string `json:"locality,omitempty"`
}

// SetupService handles first-run server initialization.
type SetupService interface {
	// Status returns the current setup state.
	Status(ctx context.Context) (*SetupStatusResponse, error)
	// ConfigureBarrier initializes the encryption barrier (embedded mode only).
	ConfigureBarrier(ctx context.Context, req *SetupBarrierRequest) (*SetupBarrierResponse, error)
	// ConfigureCA sets up the root and intermediate CA.
	ConfigureCA(ctx context.Context, req *SetupCARequest) error
	// Complete marks setup as finished.
	Complete(ctx context.Context) error
}

// Ensure setupService implements SetupService at compile time.
var _ SetupService = (*setupService)(nil)

// kvKeySetupStatus is the KV key used to persist the setup completion state.
const kvKeySetupStatus = "trusted-ca/setup/status"

// kvKeySetupCA is the KV key used to persist the CA configuration submitted during setup.
const kvKeySetupCA = "trusted-ca/setup/ca-config"

type setupService struct {
	mode    BarrierMode
	barrier db.BarrierClient
	ca      ca.TCGCA
	kv      db.KVClient
	status  atomic.Value
	logger  *slog.Logger
}

// NewSetupService creates a new setup service instance.
func NewSetupService(
	mode BarrierMode,
	barrier db.BarrierClient,
	realCA ca.TCGCA,
	kv db.KVClient,
	logger *slog.Logger,
) SetupService {
	s := &setupService{
		mode:    mode,
		barrier: barrier,
		ca:      realCA,
		kv:      kv,
		logger:  logger,
	}
	s.status.Store(SetupStatusPending)

	// Restore persisted status from KV if available.
	if kv != nil {
		if val, err := kv.Get(context.Background(), kvKeySetupStatus); err == nil && string(val) == string(SetupStatusComplete) {
			s.status.Store(SetupStatusComplete)
			logger.Info("setup: restored completed status from KV store")
		}
	}

	return s
}

// requirePending returns a SetupAlreadyCompleteError if setup has been completed.
func (s *setupService) requirePending() error {
	if s.status.Load().(SetupStatus) == SetupStatusComplete {
		return &SetupAlreadyCompleteError{}
	}
	return nil
}

// Status returns the current setup state.
func (s *setupService) Status(ctx context.Context) (*SetupStatusResponse, error) {
	caInitialized := false

	// Check barrier initialization status when available.
	if s.barrier != nil {
		barrierStatus, err := s.barrier.BarrierStatus(ctx)
		if err == nil && barrierStatus.InitializedAt != "" {
			caInitialized = true
		}
	}

	// Also check whether the CA itself reports initialized.
	if !caInitialized && s.ca != nil {
		caInitialized = s.ca.IsInitialized()
	}

	return &SetupStatusResponse{
		Status:        s.status.Load().(SetupStatus),
		Mode:          s.mode,
		CAInitialized: caInitialized,
	}, nil
}

// ConfigureBarrier initializes the encryption barrier during setup.
func (s *setupService) ConfigureBarrier(ctx context.Context, req *SetupBarrierRequest) (*SetupBarrierResponse, error) {
	if err := s.requirePending(); err != nil {
		return nil, err
	}

	switch req.Strategy {
	case "none":
		s.logger.Info("setup: barrier skipped (strategy: none)")
		return &SetupBarrierResponse{}, nil
	case "software", "":
		if req.Secret == "" {
			return nil, &SetupError{Message: "secret is required for software barrier strategy"}
		}
		if s.barrier == nil {
			return nil, &BarrierNotEnabledError{Operation: "setup-configure-barrier"}
		}
		if s.mode != BarrierModeEmbedded {
			return nil, &BarrierRemoteModeError{Operation: "setup-configure-barrier"}
		}
		return s.configureBarrierSoftware(ctx, req)
	case "shamir":
		if req.Shamir == nil {
			return nil, &SetupError{Message: "shamir configuration is required for shamir strategy"}
		}
		if req.Shamir.Threshold < 1 {
			return nil, &SetupError{Message: "shamir threshold must be at least 1"}
		}
		if req.Shamir.Total < req.Shamir.Threshold {
			return nil, &SetupError{Message: "shamir total must be >= threshold"}
		}
		if s.barrier == nil {
			return nil, &BarrierNotEnabledError{Operation: "setup-configure-barrier"}
		}
		if s.mode != BarrierModeEmbedded {
			return nil, &BarrierRemoteModeError{Operation: "setup-configure-barrier"}
		}
		return s.configureBarrierShamir(ctx, req)
	default:
		return nil, &UnsupportedBarrierStrategyError{Strategy: req.Strategy}
	}
}

// configureBarrierSoftware initializes the barrier with a software passphrase.
func (s *setupService) configureBarrierSoftware(ctx context.Context, req *SetupBarrierRequest) (*SetupBarrierResponse, error) {
	if err := s.barrier.BarrierInitialize(ctx, &db.BarrierInitializeRequest{
		Secret: req.Secret,
	}); err != nil {
		return nil, &SetupBarrierError{Operation: "initialize", Err: err}
	}
	s.logger.Info("setup: barrier initialized with software strategy")
	return &SetupBarrierResponse{}, nil
}

// configureBarrierShamir initializes the barrier with Shamir secret sharing.
func (s *setupService) configureBarrierShamir(ctx context.Context, req *SetupBarrierRequest) (*SetupBarrierResponse, error) {
	resp, err := s.barrier.BarrierInitializeShamir(ctx, &db.BarrierInitializeShamirRequest{
		Secret:      req.Secret,
		Threshold:   req.Shamir.Threshold,
		TotalShares: req.Shamir.Total,
	})
	if err != nil {
		return nil, &SetupBarrierError{Operation: "initialize-shamir", Err: err}
	}

	s.logger.Info("setup: barrier initialized with shamir strategy",
		slog.Int("threshold", resp.Threshold),
		slog.Int("total_shares", resp.TotalShares))

	return &SetupBarrierResponse{
		Threshold:  resp.Threshold,
		Total:      resp.TotalShares,
		ShareCount: resp.ShareCount,
	}, nil
}

// ConfigureCA validates CA readiness and persists the submitted configuration to KV.
func (s *setupService) ConfigureCA(ctx context.Context, req *SetupCARequest) error {
	if err := s.requirePending(); err != nil {
		return err
	}
	if req.RootCAName == "" {
		return &SetupError{Message: "root CA name is required"}
	}
	if req.IntermediateCAName == "" {
		return &SetupError{Message: "intermediate CA name is required"}
	}
	if req.KeyAlgorithm == "" {
		return &SetupError{Message: "key algorithm is required"}
	}
	if req.ValidityYears < 1 {
		return &SetupError{Message: "validity years must be at least 1"}
	}

	// Verify the CA is initialized before accepting configuration.
	if s.ca != nil && !s.ca.IsInitialized() {
		return &SetupError{Message: "CA is not initialized"}
	}

	// Persist the CA configuration to KV for audit and future reference.
	if s.kv != nil {
		data, err := json.Marshal(req)
		if err != nil {
			return &SetupError{Message: "failed to marshal CA config: " + err.Error()}
		}
		if err := s.kv.Put(ctx, kvKeySetupCA, data); err != nil {
			return &SetupError{Message: "failed to persist CA config: " + err.Error()}
		}
	}

	s.logger.Info("setup: CA configuration stored",
		slog.String("root_ca_name", req.RootCAName),
		slog.String("intermediate_ca_name", req.IntermediateCAName),
		slog.String("key_algorithm", req.KeyAlgorithm),
		slog.Int("validity_years", req.ValidityYears),
		slog.String("organization", req.Organization),
		slog.String("organizational_unit", req.OrganizationalUnit),
		slog.String("country", req.Country),
		slog.String("state", req.State),
		slog.String("locality", req.Locality))

	return nil
}

// Complete marks setup as finished, persists the state to KV, and prevents
// further setup operations.
func (s *setupService) Complete(ctx context.Context) error {
	if err := s.requirePending(); err != nil {
		return err
	}

	// Persist completion state to KV so it survives restarts.
	if s.kv != nil {
		if err := s.kv.Put(ctx, kvKeySetupStatus, []byte(SetupStatusComplete)); err != nil {
			return &SetupError{Message: "failed to persist setup status: " + err.Error()}
		}
	}

	s.status.Store(SetupStatusComplete)
	s.logger.Info("setup: initialization complete")
	return nil
}
