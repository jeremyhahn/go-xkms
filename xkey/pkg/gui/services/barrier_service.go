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

package services

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	filestorage "github.com/jeremyhahn/go-xkms/pkg/storage/file"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
)

// barrierSubdir is the subdirectory under configDir for barrier storage.
// Used as the fallback when no explicit dataDir is configured.
const barrierSubdir = "barrier"

// barrierRootKeyPath is the storage key for the sealed root key blob.
const barrierRootKeyPath = "barrier/root_key"

// strategyLabels maps strategy IDs to human-readable labels for the frontend.
var strategyLabels = map[seal.StrategyID]string{
	seal.StrategySoftware: "Software (AES-256-GCM)",
	seal.StrategyTPM2:     "TPM 2.0 Hardware",
}

// BarrierStrategyInfo describes a seal strategy's availability for the frontend.
type BarrierStrategyInfo struct {
	ID             string `json:"id"`
	Available      bool   `json:"available"`
	HardwareBacked bool   `json:"hardware_backed"`
	Label          string `json:"label"`
}

// BaseBackendFactory creates the storage backend used underneath the barrier.
// The storageDir parameter is the barrier subdirectory path.
type BaseBackendFactory func(storageDir string) (storage.Backend, error)

// BarrierService wraps the seal.Barrier for GUI integration, providing
// cross-platform encrypted storage with automatic strategy selection.
type BarrierService struct {
	mu            sync.Mutex
	ctx           context.Context
	log           *slog.Logger
	barrier       *seal.Barrier
	configDir     string
	dataDir       string
	baseBackendFn BaseBackendFactory

	// tpmSealerFn is called to obtain a TPM2 sealer when probing strategies.
	// If nil, TPM2 strategy is unavailable.
	tpmSealerFn func() types.Sealer

	// postUnsealHook is called after a successful Unseal() to allow the
	// application to initialize services that depend on the barrier backend
	// (e.g., FIDO2 storage, OATH, static passwords). Called outside the
	// mutex to allow re-entrant access to BarrierService methods.
	postUnsealHook func() error

	// auditLog stores the audit logger for security event logging.
	auditLog atomic.Pointer[audit.Logger]

	// lastStrategy records the strategy used during the most recent
	// Initialize or Unseal so that GetSealInfo can display the actual
	// strategy even when the barrier object is nil (sealed between sessions).
	lastStrategy string
}

// NewBarrierService creates a new BarrierService. By default, encrypted data
// is stored under configDir/barrier/. Call SetDataDir to override the storage
// location (e.g., ~/.xkey/data/) so that all data is transparently encrypted
// in a dedicated data directory. The barrier is not initialized until
// Initialize or Unseal is called.
func NewBarrierService(configDir string, log *slog.Logger) *BarrierService {
	return &BarrierService{
		configDir: configDir,
		log:       log.With("component", "barrier_service"),
	}
}

// SetContext is the Wails lifecycle hook that provides the application context.
func (s *BarrierService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// SetDataDir overrides the default barrier storage directory. When set,
// encrypted data is stored in dataDir instead of configDir/barrier/.
func (s *BarrierService) SetDataDir(dir string) {
	s.dataDir = dir
}

// SetTPMSealerFunc sets the function used to obtain a TPM2 sealer. When the
// function returns a non-nil sealer, TPM2 strategy becomes available.
func (s *BarrierService) SetTPMSealerFunc(fn func() types.Sealer) {
	s.tpmSealerFn = fn
}

// SetBaseBackendFactory sets the function used to create the base storage backend.
// When nil (the default), filestorage.New is used. Override with a LUKS backend
// factory when LUKS is the selected storage type.
func (s *BarrierService) SetBaseBackendFactory(fn BaseBackendFactory) {
	s.baseBackendFn = fn
}

// SetPostUnsealHook registers a callback that runs after every successful
// Unseal(). The hook is invoked outside the service mutex so the callback
// may safely call BarrierService methods (e.g. GetBackend, IsUnsealed).
// Errors from the hook are logged but do not affect the unseal result.
func (s *BarrierService) SetPostUnsealHook(fn func() error) {
	s.mu.Lock()
	s.postUnsealHook = fn
	s.mu.Unlock()
}

// SetLastStrategy records the barrier strategy from persisted config so
// that GetSealInfo can display the correct strategy before the barrier
// is unsealed in the current session.
func (s *BarrierService) SetLastStrategy(strategy string) {
	s.mu.Lock()
	s.lastStrategy = strategy
	s.mu.Unlock()
}

// SetAuditLogger sets the audit logger for security event logging.
func (s *BarrierService) SetAuditLogger(l audit.Logger) {
	s.auditLog.Store(&l)
}

// logBarrierEvent logs a barrier-related audit event.
func (s *BarrierService) logBarrierEvent(op audit.OperationType, success bool, err error, details map[string]any) {
	if p := s.auditLog.Load(); p != nil {
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		(*p).Log(audit.Entry{
			Timestamp: time.Now(),
			Operation: op,
			Success:   success,
			Error:     errStr,
			Details:   details,
		})
	}
}

// IsInitialized returns true if the barrier root key exists in storage.
// This indicates that Initialize() was called and completed successfully.
// A barrier can be initialized but sealed (not yet unlocked with the
// correct password). Just having the storage directory is not sufficient;
// the root key must exist for the barrier to be considered initialized.
//
// Both the primary storageDir (dataDir if set) and the fallback
// configDir/barrier/ path are probed so that an initialization performed
// before dataDir was configured is still detected.
func (s *BarrierService) IsInitialized() bool {
	return s.checkInitialized() != ""
}

// ProbeStrategies returns a list of sealing strategies with their current
// availability. Software is always available. TPM2 is available only when
// tpmSealerFn returns a non-nil sealer.
func (s *BarrierService) ProbeStrategies() []BarrierStrategyInfo {
	return s.probeStrategiesUnlocked()
}

// BestStrategy returns the best available strategy according to the default
// preference order. Hardware-backed strategies are preferred over software.
func (s *BarrierService) BestStrategy() (*BarrierStrategyInfo, error) {
	return s.bestStrategyUnlocked()
}

// Initialize creates a new barrier with a fresh root key. The barrier data
// is stored under the directory returned by storageDir() using a file
// storage backend.
//
// The strategyID parameter specifies which sealing strategy to use (e.g.,
// "software", "tpm2"). This must be explicitly chosen by the caller — no
// auto-detection or fallback is performed.
//
// A password is required when the strategy is software-based.
// After initialization the barrier transitions to the unsealed state.
func (s *BarrierService) Initialize(password, strategyID string) error {
	s.mu.Lock()
	// NOTE: mu is manually unlocked before the post-unseal hook (same
	// pattern as Unseal) to allow re-entrant BarrierService calls.
	// All early returns must unlock explicitly.
	unlocked := false
	defer func() {
		if !unlocked {
			s.mu.Unlock()
		}
	}()

	// Fall back to the best available strategy when none is specified.
	if strategyID == "" {
		best, err := s.bestStrategyUnlocked()
		if err != nil {
			return &ErrBarrierStrategyUnavailable{Strategy: ""}
		}
		strategyID = best.ID
	}

	storageDir := s.storageDir()
	s.log.Info("barrier: Initialize called",
		slog.String("storage_dir", storageDir),
		slog.String("strategy", strategyID),
		slog.Bool("has_password", password != ""))

	// Check whether the barrier directory already has data.
	if _, err := os.Stat(storageDir); err == nil {
		base, err := s.createBaseBackend(storageDir)
		if err != nil {
			s.log.Error("barrier: createBaseBackend failed (existing dir check)", "error", err)
			return err
		}
		exists, err := base.Exists(context.Background(), barrierRootKeyPath)
		if err != nil {
			_ = base.Close()
			s.log.Error("barrier: root key existence check failed", "error", err)
			return err
		}
		if exists {
			_ = base.Close()
			return ErrBarrierAlreadyInit
		}
		_ = base.Close()
	}

	// Validate password for software strategy.
	if strategyID == string(seal.StrategySoftware) && password == "" {
		s.log.Error("barrier: software strategy requires password but none provided")
		return ErrBarrierPasswordRequired
	}

	// Create the storage directory with restrictive permissions.
	if err := os.MkdirAll(storageDir, 0700); err != nil {
		s.log.Error("barrier: failed to create storage directory",
			"path", storageDir, "error", err)
		return err
	}

	strategy, stratErr := s.assembleStrategy(strategyID)
	if stratErr != nil {
		s.log.Error("barrier: strategy unavailable",
			"strategy", strategyID, "error", stratErr)
		return stratErr
	}

	base, err := s.createBaseBackend(storageDir)
	if err != nil {
		s.log.Error("barrier: createBaseBackend failed", "error", err)
		return err
	}

	barrier, bErr := seal.NewBarrier(s.log, base, seal.BarrierConfig{
		RootKeyPath:     barrierRootKeyPath,
		PreferenceOrder: seal.DefaultPreferenceOrder,
	}, strategy)
	if bErr != nil {
		_ = base.Close()
		s.log.Error("barrier: NewBarrier failed", "error", bErr)
		return bErr
	}

	ctx := s.context()
	if initErr := barrier.Initialize(ctx, seal.Credentials{Secret: password}); initErr != nil {
		_ = base.Close()
		s.log.Error("barrier: barrier.Initialize failed",
			"strategy", strategyID, "error", initErr)
		s.logBarrierEvent(audit.OpBarrierInitialized, false, initErr, map[string]any{"strategy": strategyID})
		return initErr
	}

	s.barrier = barrier
	s.lastStrategy = strategyID
	hook := s.postUnsealHook
	s.log.Info("barrier initialized", slog.String("strategy", strategyID))
	s.logBarrierEvent(audit.OpBarrierInitialized, true, nil, map[string]any{"strategy": strategyID})
	unlocked = true
	s.mu.Unlock()

	// Run the post-unseal hook outside the mutex. Initialize leaves the
	// barrier in the unsealed state, so barrier-dependent services (data
	// directory, PIN, FIDO2, etc.) can be initialized immediately.
	if hook != nil {
		if err := hook(); err != nil {
			s.log.Warn("post-init hook failed", "error", err)
		}
	}
	return nil
}

// Unseal loads an existing barrier from disk and transitions it to the
// unsealed state. Returns ErrBarrierNotInitialized if the barrier directory
// does not exist. After a successful unseal, the post-unseal hook (if set)
// is invoked to initialize barrier-dependent services.
//
// The strategyID parameter specifies which sealing strategy was used to
// initialize the barrier. This must match the strategy persisted in config
// — no auto-detection or fallback is performed.
//
// Both the primary storageDir and the fallback configDir/barrier/ path are
// probed so that an initialization performed before dataDir was configured
// is still found.
func (s *BarrierService) Unseal(password, strategyID string) error {
	s.mu.Lock()

	// When the frontend calls Unseal with only a password, strategyID
	// may be empty. Fall back to the best available strategy so the
	// manual unseal dialog works without passing a strategy explicitly.
	if strategyID == "" {
		best, err := s.bestStrategyUnlocked()
		if err != nil {
			s.mu.Unlock()
			return &ErrBarrierStrategyUnavailable{Strategy: ""}
		}
		strategyID = best.ID
	}

	storageDir := s.checkInitialized()
	if storageDir == "" {
		// Barrier root key does not exist — initialize a new barrier instead
		// of returning an error. This handles the case where the config says
		// the barrier is initialized but the root key was never created
		// (e.g., wizard failed mid-flight). The user is providing their
		// password now, so we can create the barrier transparently.
		s.log.Warn("barrier: root key not found, initializing new barrier",
			"strategy", strategyID)
		s.mu.Unlock()
		return s.Initialize(password, strategyID)
	}

	strategy, stratErr := s.assembleStrategy(strategyID)
	if stratErr != nil {
		s.log.Error("barrier: strategy unavailable for unseal",
			"strategy", strategyID, "error", stratErr)
		s.mu.Unlock()
		return stratErr
	}

	base, err := s.createBaseBackend(storageDir)
	if err != nil {
		s.mu.Unlock()
		return err
	}

	barrier, bErr := seal.NewBarrier(s.log, base, seal.BarrierConfig{
		RootKeyPath:     barrierRootKeyPath,
		PreferenceOrder: seal.DefaultPreferenceOrder,
	}, strategy)
	if bErr != nil {
		_ = base.Close()
		s.mu.Unlock()
		return bErr
	}

	ctx := s.context()
	if err := barrier.Unseal(ctx, seal.Credentials{Secret: password}); err != nil {
		_ = base.Close()
		s.mu.Unlock()
		s.logBarrierEvent(audit.OpBarrierUnsealed, false, err, map[string]any{"strategy": strategyID})
		return err
	}

	s.barrier = barrier
	s.lastStrategy = strategyID
	hook := s.postUnsealHook
	s.log.Info("barrier unsealed", slog.String("strategy", strategyID))
	s.logBarrierEvent(audit.OpBarrierUnsealed, true, nil, map[string]any{"strategy": strategyID})
	s.mu.Unlock()

	// Run the post-unseal hook outside the mutex to allow re-entrant
	// calls to BarrierService methods (e.g. GetBackend, IsUnsealed).
	if hook != nil {
		if err := hook(); err != nil {
			s.log.Warn("post-unseal hook failed", "error", err)
		}
	}
	return nil
}

// Seal transitions the barrier to the sealed state, zeroing the data
// encryption key. Returns ErrBarrierNotInitialized if the barrier has
// not been created.
func (s *BarrierService) Seal() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.barrier == nil {
		return ErrBarrierNotInitialized
	}
	err := s.barrier.Seal()
	if err != nil {
		s.logBarrierEvent(audit.OpBarrierSealed, false, err, nil)
		return err
	}
	s.logBarrierEvent(audit.OpBarrierSealed, true, nil, nil)
	return nil
}

// ChangePassword re-seals the barrier root key with new credentials.
// The barrier must be initialized and unsealed. For hardware-backed
// strategies this is a no-op because those strategies do not use
// password-derived wrapping keys.
func (s *BarrierService) ChangePassword(newPassword string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.barrier == nil {
		return ErrBarrierNotInitialized
	}

	ctx := s.context()
	if err := s.barrier.ChangePassword(ctx, seal.Credentials{Secret: newPassword}); err != nil {
		s.logBarrierEvent(audit.OpBarrierPasswordChanged, false, err, nil)
		return err
	}

	s.logBarrierEvent(audit.OpBarrierPasswordChanged, true, nil, nil)
	s.log.Info("barrier password changed")
	return nil
}

// Status returns the current barrier status. If the barrier has not been
// initialized, a zero-value BarrierStatus is returned.
func (s *BarrierService) Status() *seal.BarrierStatus {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.barrier == nil {
		return &seal.BarrierStatus{Sealed: true}
	}
	return s.barrier.Status()
}

// IsUnsealed reports whether the barrier is in the unsealed state.
// Returns false if the barrier has not been initialized.
func (s *BarrierService) IsUnsealed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.barrier == nil {
		return false
	}
	return !s.barrier.IsSealed()
}

// GetBackend returns the barrier as a storage.Backend for use by other
// services that need encrypted storage. Returns nil if the barrier has
// not been initialized or unsealed.
func (s *BarrierService) GetBackend() storage.Backend {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.barrier == nil {
		return nil
	}
	return s.barrier
}

// storageDir returns the directory used for barrier encrypted data storage.
// If dataDir has been set via SetDataDir, it is returned. Otherwise, the
// default configDir/barrier/ path is used for backward compatibility.
func (s *BarrierService) storageDir() string {
	if s.dataDir != "" {
		return s.dataDir
	}
	return filepath.Join(s.configDir, barrierSubdir)
}

// checkInitialized probes both the primary storageDir and the fallback
// configDir/barrier/ path for an existing root key. Returns the directory
// where the root key was found, or empty string if not initialized.
// This method is safe to call without holding s.mu as it performs
// read-only filesystem operations.
func (s *BarrierService) checkInitialized() string {
	// Probe primary path first.
	primary := s.storageDir()
	if s.probeRootKey(primary) {
		return primary
	}

	// If primary differs from fallback, probe fallback.
	fallback := filepath.Join(s.configDir, barrierSubdir)
	if fallback != primary && s.probeRootKey(fallback) {
		return fallback
	}

	return ""
}

// probeRootKey checks whether the barrier root key exists in the given
// directory by creating a temporary storage backend and querying for the
// key. Returns false if the directory does not exist, the backend cannot
// be created, or the key is not found.
func (s *BarrierService) probeRootKey(dir string) bool {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return false
	}
	base, err := s.createBaseBackend(dir)
	if err != nil {
		return false
	}
	defer func() { _ = base.Close() }()

	exists, err := base.Exists(context.Background(), barrierRootKeyPath)
	if err != nil {
		return false
	}
	return exists
}

// assembleStrategy builds the single sealing strategy matching strategyID.
// No fallback strategies are included — if the selected strategy is
// unavailable, the caller must surface the error.
func (s *BarrierService) assembleStrategy(strategyID string) (seal.SealingStrategy, error) {
	switch seal.StrategyID(strategyID) {
	case seal.StrategyTPM2:
		if s.tpmSealerFn == nil {
			return nil, &ErrBarrierStrategyUnavailable{Strategy: strategyID}
		}
		sealer := s.tpmSealerFn()
		if sealer == nil || !sealer.CanSeal() {
			return nil, &ErrBarrierStrategyUnavailable{Strategy: strategyID}
		}
		return seal.NewTPM2Strategy(sealer, nil), nil
	case seal.StrategySoftware:
		return seal.NewSoftwareStrategy(), nil
	default:
		return nil, &ErrBarrierStrategyUnavailable{Strategy: strategyID}
	}
}

// createBaseBackend creates the base storage backend for the barrier.
// Uses the registered factory if set, otherwise defaults to filestorage.New.
func (s *BarrierService) createBaseBackend(storageDir string) (storage.Backend, error) {
	if s.baseBackendFn != nil {
		return s.baseBackendFn(storageDir)
	}
	return filestorage.New(storageDir)
}

// BarrierSealInfo describes the barrier's seal state for the frontend.
type BarrierSealInfo struct {
	Initialized    bool   `json:"initialized"`
	Sealed         bool   `json:"sealed"`
	Strategy       string `json:"strategy"`
	StrategyLabel  string `json:"strategy_label"`
	HardwareBacked bool   `json:"hardware_backed"`
	RootKeyPath    string `json:"root_key_path"`
}

// GetSealInfo returns a snapshot of the barrier's seal state for display
// on the Sealed Data page. It checks whether the barrier directory and
// root key exist (initialized), whether the barrier is sealed or unsealed,
// and what strategy is active.
//
// Both the primary storageDir and the fallback configDir/barrier/ path are
// probed so that an initialization performed before dataDir was configured
// is detected correctly.
func (s *BarrierService) GetSealInfo() *BarrierSealInfo {
	s.mu.Lock()
	defer s.mu.Unlock()

	foundDir := s.checkInitialized()

	info := &BarrierSealInfo{
		RootKeyPath: filepath.Join(s.storageDir(), barrierRootKeyPath),
	}

	if foundDir != "" {
		info.Initialized = true
		// Update RootKeyPath to actual found location.
		info.RootKeyPath = filepath.Join(foundDir, barrierRootKeyPath)
	}

	// If the barrier object is live, pull strategy details from it.
	if s.barrier != nil {
		status := s.barrier.Status()
		info.Sealed = status.Sealed
		info.HardwareBacked = status.HardwareBacked
		info.Strategy = string(status.Strategy)
		if label, ok := strategyLabels[status.Strategy]; ok {
			info.StrategyLabel = label
		} else {
			info.StrategyLabel = string(status.Strategy)
		}
	} else if info.Initialized {
		// Barrier exists on disk but has not been unsealed in this session.
		info.Sealed = true
		// Use the strategy from the last Initialize/Unseal if available,
		// otherwise fall back to probing available strategies.
		if s.lastStrategy != "" {
			sid := seal.StrategyID(s.lastStrategy)
			info.Strategy = s.lastStrategy
			if label, ok := strategyLabels[sid]; ok {
				info.StrategyLabel = label
			} else {
				info.StrategyLabel = s.lastStrategy
			}
			// Check hardware-backed from the probed strategies list.
			for _, p := range s.probeStrategiesUnlocked() {
				if p.ID == s.lastStrategy {
					info.HardwareBacked = p.HardwareBacked
					break
				}
			}
		} else {
			best, err := s.bestStrategyUnlocked()
			if err == nil {
				info.Strategy = best.ID
				info.HardwareBacked = best.HardwareBacked
				info.StrategyLabel = best.Label
			}
		}
	}

	return info
}

// bestStrategyUnlocked returns the best strategy without acquiring the mutex.
// Callers must hold s.mu.
func (s *BarrierService) bestStrategyUnlocked() (*BarrierStrategyInfo, error) {
	probed := s.probeStrategiesUnlocked()
	available := make(map[string]*BarrierStrategyInfo, len(probed))
	for i := range probed {
		if probed[i].Available {
			available[probed[i].ID] = &probed[i]
		}
	}
	for _, id := range seal.DefaultPreferenceOrder {
		if info, ok := available[string(id)]; ok {
			return info, nil
		}
	}
	return nil, seal.ErrNoAvailableStrategy
}

// probeStrategiesUnlocked is the non-locking version of ProbeStrategies.
func (s *BarrierService) probeStrategiesUnlocked() []BarrierStrategyInfo {
	strategies := []BarrierStrategyInfo{
		{
			ID:             string(seal.StrategySoftware),
			Available:      true,
			HardwareBacked: false,
			Label:          strategyLabels[seal.StrategySoftware],
		},
	}
	if s.tpmSealerFn != nil {
		sealer := s.tpmSealerFn()
		// Check both non-nil AND CanSeal() to match the inner barrier's
		// TPM2Strategy.Available() check. Without CanSeal(), the service
		// may report TPM2 as "best" (skipping password guard) while the
		// barrier internally falls to Software with an empty password.
		available := sealer != nil && sealer.CanSeal()
		strategies = append(strategies, BarrierStrategyInfo{
			ID:             string(seal.StrategyTPM2),
			Available:      available,
			HardwareBacked: true,
			Label:          strategyLabels[seal.StrategyTPM2],
		})
	}
	return strategies
}

// context returns the service context, falling back to context.Background
// when no context has been set via the Wails lifecycle.
func (s *BarrierService) context() context.Context {
	if s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}
