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
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
)

// barrierSubdir is the subdirectory under configDir for barrier storage.
// Used as the fallback when no explicit dataDir is configured.
const barrierSubdir = "barrier"

// barrierRootKeyPath is the storage key for the sealed root key blob.
const barrierRootKeyPath = "barrier/root_key"

// strategyLabels maps strategy IDs to human-readable labels for the frontend.
var strategyLabels = map[xkms.StrategyID]string{
	xkms.StrategyPassphrase: "Passphrase (AES-256-GCM)",
	xkms.StrategyTPM2:       "TPM 2.0 Hardware",
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
type BaseBackendFactory func(storageDir string) (xkms.StorageBackend, error)

// BarrierService wraps the seal.Barrier for GUI integration, providing
// cross-platform encrypted storage with automatic strategy selection.
type BarrierService struct {
	mu      sync.Mutex
	ctx     context.Context
	log     *slog.Logger
	barrier *xkms.Barrier
	// barrierBackend wraps barrier so it satisfies storage.Backend (which now
	// requires PutIfAbsent). Cached so a single instance — and thus a single
	// mutex — guards check-then-write across all callers in this process.
	barrierBackend *xkms.BarrierBackend
	configDir      string
	dataDir        string
	baseBackendFn  BaseBackendFactory

	// tpmSealerFn is called to obtain a TPM2 sealer when probing strategies.
	// If nil, TPM2 strategy is unavailable.
	tpmSealerFn func() xkms.Sealer

	// externalStrategyFn is called to obtain a pkcs11 or cloud KMS
	// (aws_kms/gcp_kms/azure_kv/vault) sealing strategy when assembleStrategy
	// needs one. If nil, those strategies are unavailable: BarrierService has
	// no HSM or cloud backend wiring of its own -- the caller (xkey's
	// headless `extension serve` or a future GUI flow) builds the backend
	// from its own configuration and injects the assembled strategy here, the
	// same pattern SetTPMSealerFunc uses for TPM2 (go-xkms#757).
	externalStrategyFn func(strategyID string) (xkms.SealingStrategy, error)

	// postUnsealHook is called after a successful Unseal() to allow the
	// application to initialize services that depend on the barrier backend
	// (e.g., FIDO2 storage, OATH, static passwords). Called outside the
	// mutex to allow re-entrant access to BarrierService methods.
	postUnsealHook func() error

	// sealStateHook is called after every successful Seal, Unseal and
	// Initialize, outside the mutex, so the application can follow the
	// barrier's seal state (e.g. start or stop the IPC listener).
	sealStateHook func()

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
func (s *BarrierService) SetTPMSealerFunc(fn func() xkms.Sealer) {
	s.tpmSealerFn = fn
}

// SetExternalStrategyFunc sets the function used to obtain a pkcs11 or cloud
// KMS sealing strategy (aws_kms, gcp_kms, azure_kv, or vault, identified by
// strategyID) when Initialize or Unseal is called with one of those strategy
// IDs. When nil (the default), those strategies are unavailable and
// assembleStrategy reports ErrBarrierStrategyUnavailable.
func (s *BarrierService) SetExternalStrategyFunc(fn func(strategyID string) (xkms.SealingStrategy, error)) {
	s.mu.Lock()
	s.externalStrategyFn = fn
	s.mu.Unlock()
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

// SetSealStateHook registers fn to run after every successful seal-state
// change: Seal, Unseal (including a re-unseal in place) and Initialize. fn
// runs outside the service mutex and may call back into the service.
func (s *BarrierService) SetSealStateHook(fn func()) {
	s.mu.Lock()
	s.sealStateHook = fn
	s.mu.Unlock()
}

// notifySealState runs the seal-state hook, if one is registered. The caller
// must not hold s.mu.
func (s *BarrierService) notifySealState() {
	s.mu.Lock()
	hook := s.sealStateHook
	s.mu.Unlock()
	if hook != nil {
		hook()
	}
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

// logBarrierEvent logs a barrier-related audit event. Every barrier
// operation is SeveritySecurity, so the caller must propagate a non-nil
// return and fail the request rather than proceed unaudited.
func (s *BarrierService) logBarrierEvent(op audit.OperationType, success bool, err error, details map[string]any) error {
	p := s.auditLog.Load()
	if p == nil {
		return nil
	}
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	return (*p).Log(audit.Entry{
		Timestamp: time.Now(),
		Operation: op,
		Success:   success,
		Error:     errStr,
		Details:   details,
	})
}

// barrierAuditErr logs a barrier-related audit event and reports the
// error the caller should return: the audit write failure if
// logBarrierEvent returned one (a SeveritySecurity write failure must
// fail the request), otherwise origErr so the operation's own failure
// reason is preserved.
func (s *BarrierService) barrierAuditErr(op audit.OperationType, success bool, origErr error, details map[string]any) error {
	if auditErr := s.logBarrierEvent(op, success, origErr, details); auditErr != nil {
		return auditErr
	}
	return origErr
}

// IsInitialized returns true if the barrier root key exists in storage.
// This indicates that Initialize() was called and completed successfully.
// A barrier can be initialized but sealed (not yet unlocked with the
// correct password). Just having the storage directory is not sufficient;
// the root key must exist for the barrier to be considered initialized.
func (s *BarrierService) IsInitialized() bool {
	return s.checkInitialized() != ""
}

// ProbeStrategies returns a list of sealing strategies with their current
// availability. Passphrase is always available. TPM2 is available only when
// tpmSealerFn returns a non-nil sealer.
func (s *BarrierService) ProbeStrategies() []BarrierStrategyInfo {
	return s.probeStrategiesUnlocked()
}

// BestStrategy returns the best available strategy according to the default
// preference order. Hardware-backed strategies are preferred over passphrase.
func (s *BarrierService) BestStrategy() (*BarrierStrategyInfo, error) {
	return s.bestStrategyUnlocked()
}

// Initialize creates a new barrier with a fresh root key. The barrier data
// is stored under the directory returned by storageDir() using a file
// storage backend.
//
// The strategyID parameter specifies which sealing strategy to use (e.g.,
// "passphrase", "tpm2"). This must be explicitly chosen by the caller — no
// auto-detection or fallback is performed.
//
// A password is required when the strategy is passphrase.
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

	// UX-only preflight: surface ErrBarrierAlreadyInit early so the GUI can
	// show a friendly message before any strategy/password work. This check
	// is advisory — the authoritative guard against concurrent initializers
	// is the atomic PutIfAbsent compare-and-set inside barrier.Initialize,
	// which returns ErrAlreadyInitialized to the race loser.
	if _, err := os.Stat(storageDir); err == nil {
		base, err := s.createBaseBackend(storageDir)
		if err != nil {
			s.log.Error("barrier: createBaseBackend failed (existing dir check)", "error", err)
			return err
		}
		exists, err := base.Exists(context.Background(), barrierRootKeyPath)
		if err != nil {
			s.log.Error("barrier: root key existence check failed", "error", err)
			if closeErr := base.Close(); closeErr != nil {
				s.log.Warn("barrier: failed to close base backend after existence check failure", "error", closeErr)
			}
			return err
		}
		if exists {
			if closeErr := base.Close(); closeErr != nil {
				s.log.Warn("barrier: failed to close base backend after already-initialized check", "error", closeErr)
			}
			return ErrBarrierAlreadyInit
		}
		if closeErr := base.Close(); closeErr != nil {
			s.log.Warn("barrier: failed to close base backend after existing-dir preflight", "error", closeErr)
		}
	}

	// Validate password for the passphrase strategy: a missing password is
	// caught here before the deferred-passphrase strategy errors deeper in
	// the barrier.
	if strategyID == string(xkms.StrategyPassphrase) && password == "" {
		s.log.Error("barrier: passphrase strategy requires password but none provided")
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

	barrier, bErr := xkms.NewBarrier(s.log, base, xkms.BarrierConfig{
		RootKeyPath:     barrierRootKeyPath,
		PreferenceOrder: []xkms.StrategyID{strategy.ID()},
	}, strategy)
	if bErr != nil {
		closeErr := base.Close()
		s.log.Error("barrier: NewBarrier failed", "error", bErr)
		return errors.Join(bErr, closeErr)
	}

	ctx := s.context()
	// CredentialsFor, not NewCredentials: strategyID may be hardware-backed
	// (TPM2), in which case password is legitimately empty and must reach the
	// strategy as the zero Credentials rather than tripping NewCredentials'
	// "refuses empty input" guard. The password string itself is a Go string
	// and cannot be wiped either way, so CredentialsFor's simplicity costs no
	// additional exposure here.
	creds, credErr := xkms.CredentialsFor(ctx, []byte(password))
	if credErr != nil {
		closeErr := base.Close()
		s.log.Error("barrier: CredentialsFor failed", "error", credErr)
		return errors.Join(credErr, closeErr)
	}
	defer creds.Secret.Destroy()

	if initErr := barrier.Initialize(ctx, creds); initErr != nil {
		closeErr := base.Close()
		s.log.Error("barrier: barrier.Initialize failed",
			"strategy", strategyID, "error", initErr)
		if auditErr := s.logBarrierEvent(audit.OpBarrierInitialized, false, initErr, map[string]any{"strategy": strategyID}); auditErr != nil {
			return errors.Join(auditErr, closeErr)
		}
		return errors.Join(initErr, closeErr)
	}

	s.barrier = barrier
	s.barrierBackend = xkms.NewBarrierBackend(barrier)
	s.lastStrategy = strategyID
	hook := s.postUnsealHook
	s.log.Info("barrier initialized", slog.String("strategy", strategyID))
	auditErr := s.logBarrierEvent(audit.OpBarrierInitialized, true, nil, map[string]any{"strategy": strategyID})
	unlocked = true
	s.mu.Unlock()
	if auditErr != nil {
		s.notifySealState()
		return auditErr
	}

	// Run the post-unseal hook outside the mutex. Initialize leaves the
	// barrier in the unsealed state, so barrier-dependent services (data
	// directory, PIN, FIDO2, etc.) can be initialized immediately.
	if hook != nil {
		if err := hook(); err != nil {
			s.log.Warn("post-init hook failed", "error", err)
		}
	}
	s.notifySealState()
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
func (s *BarrierService) Unseal(password, strategyID string) error {
	s.mu.Lock()

	// Re-unseal in place when this process already holds the barrier and
	// merely sealed it (the app-lock path). The downstream stores wired by
	// the post-unseal hook hold a BarrierBackend wrapping THIS object, and
	// the hook runs at most once per process, so constructing a replacement
	// barrier here would leave every one of them bound to the sealed object
	// with no route back. Unsealing the existing object restores them all
	// and reuses the open base backend instead of opening a second one.
	//
	// This runs before strategyID is resolved because the strategy is not an
	// input here: the barrier reads it from the sealed root key blob and
	// looks it up in its own registry. Resolving a "best available" strategy
	// first would let a TPM-capable machine pick a different ID than the one
	// the barrier was sealed with and fall through to the rebuild below,
	// stranding every store for the sake of an argument that is not used.
	if s.barrier != nil && s.barrier.IsSealed() {
		// CredentialsFor: see the Initialize comment above — the active
		// strategy may be hardware-backed and password may be empty.
		ctx := s.context()
		creds, credErr := xkms.CredentialsFor(ctx, []byte(password))
		if credErr != nil {
			s.mu.Unlock()
			return s.barrierAuditErr(audit.OpBarrierUnsealed, false, credErr, map[string]any{"strategy": s.lastStrategy})
		}
		defer creds.Secret.Destroy()

		if err := s.barrier.Unseal(ctx, creds); err != nil {
			s.mu.Unlock()
			return s.barrierAuditErr(audit.OpBarrierUnsealed, false, err, map[string]any{"strategy": s.lastStrategy})
		}
		s.log.Info("barrier re-unsealed in place", slog.String("strategy", s.lastStrategy))
		auditErr := s.logBarrierEvent(audit.OpBarrierUnsealed, true, nil, map[string]any{"strategy": s.lastStrategy})
		s.mu.Unlock()
		s.notifySealState()
		return auditErr
	}

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

	barrier, bErr := xkms.NewBarrier(s.log, base, xkms.BarrierConfig{
		RootKeyPath:     barrierRootKeyPath,
		PreferenceOrder: []xkms.StrategyID{strategy.ID()},
	}, strategy)
	if bErr != nil {
		closeErr := base.Close()
		s.mu.Unlock()
		return errors.Join(bErr, closeErr)
	}

	ctx := s.context()
	// CredentialsFor: see the Initialize comment above — the active strategy
	// may be hardware-backed and password may be empty.
	creds, credErr := xkms.CredentialsFor(ctx, []byte(password))
	if credErr != nil {
		closeErr := base.Close()
		s.mu.Unlock()
		return errors.Join(s.barrierAuditErr(audit.OpBarrierUnsealed, false, credErr, map[string]any{"strategy": strategyID}), closeErr)
	}
	defer creds.Secret.Destroy()

	if err := barrier.Unseal(ctx, creds); err != nil {
		closeErr := base.Close()
		s.mu.Unlock()
		return errors.Join(s.barrierAuditErr(audit.OpBarrierUnsealed, false, err, map[string]any{"strategy": strategyID}), closeErr)
	}

	s.barrier = barrier
	s.barrierBackend = xkms.NewBarrierBackend(barrier)
	s.lastStrategy = strategyID
	hook := s.postUnsealHook
	s.log.Info("barrier unsealed", slog.String("strategy", strategyID))
	auditErr := s.logBarrierEvent(audit.OpBarrierUnsealed, true, nil, map[string]any{"strategy": strategyID})
	s.mu.Unlock()
	if auditErr != nil {
		s.notifySealState()
		return auditErr
	}

	// Run the post-unseal hook outside the mutex to allow re-entrant
	// calls to BarrierService methods (e.g. GetBackend, IsUnsealed).
	if hook != nil {
		if err := hook(); err != nil {
			s.log.Warn("post-unseal hook failed", "error", err)
		}
	}
	s.notifySealState()
	return nil
}

// Seal transitions the barrier to the sealed state, zeroing the data
// encryption key. Returns ErrBarrierNotInitialized if the barrier has
// not been created.
func (s *BarrierService) Seal() error {
	s.mu.Lock()
	if s.barrier == nil {
		s.mu.Unlock()
		return ErrBarrierNotInitialized
	}
	if err := s.barrier.Seal(); err != nil {
		auditErr := s.barrierAuditErr(audit.OpBarrierSealed, false, err, nil)
		s.mu.Unlock()
		return auditErr
	}
	auditErr := s.logBarrierEvent(audit.OpBarrierSealed, true, nil, nil)
	s.mu.Unlock()

	s.notifySealState()
	return auditErr
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
	// CredentialsFor: ChangePassword is a no-op for hardware-backed
	// strategies, which are called with an empty newPassword by design (see
	// the doc comment above); NewCredentials would reject that empty input.
	creds, credErr := xkms.CredentialsFor(ctx, []byte(newPassword))
	if credErr != nil {
		return s.barrierAuditErr(audit.OpBarrierPasswordChanged, false, credErr, nil)
	}
	defer creds.Secret.Destroy()

	if err := s.barrier.ChangePassword(ctx, creds); err != nil {
		return s.barrierAuditErr(audit.OpBarrierPasswordChanged, false, err, nil)
	}

	if auditErr := s.logBarrierEvent(audit.OpBarrierPasswordChanged, true, nil, nil); auditErr != nil {
		return auditErr
	}
	s.log.Info("barrier password changed")
	return nil
}

// Status returns the current barrier status. If the barrier has not been
// initialized, a zero-value BarrierStatus is returned.
func (s *BarrierService) Status() *xkms.BarrierStatus {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.barrier == nil {
		return &xkms.BarrierStatus{Sealed: true}
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

// IsSealed reports whether this process holds a barrier that is currently
// sealed. Unlike IsInitialized it never touches storage, so it is cheap
// enough to call from a seal-state hook. A process that holds no barrier
// (storage without one, or a barrier not yet opened) is not sealed.
func (s *BarrierService) IsSealed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.barrier != nil && s.barrier.IsSealed()
}

// GetBarrier returns the underlying barrier for callers that need its direct
// Encrypt/Decrypt rather than the KV-store view GetBackend provides -- sealing
// a value that must stay embedded in another record instead of becoming its
// own storage entry, e.g. the phone pairing file's Noise static private key
// (#42). Returns nil if the barrier has not been initialized; callers must
// check for a nil *xkms.Barrier before handing it to an interface parameter,
// or the typed nil will not compare equal to a nil interface.
func (s *BarrierService) GetBarrier() *xkms.Barrier {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.barrier
}

// GetBackend returns the barrier as a storage.Backend for use by other
// services that need encrypted storage. Returns nil if the barrier has
// not been initialized or unsealed.
func (s *BarrierService) GetBackend() xkms.StorageBackend {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.barrier == nil {
		return nil
	}
	if s.barrierBackend == nil {
		s.barrierBackend = xkms.NewBarrierBackend(s.barrier)
	}
	return s.barrierBackend
}

// storageDir returns the directory used for barrier encrypted data storage.
// If dataDir has been set via SetDataDir, it is returned. Otherwise, the
// default configDir/barrier/ path is used.
func (s *BarrierService) storageDir() string {
	if s.dataDir != "" {
		return s.dataDir
	}
	return filepath.Join(s.configDir, barrierSubdir)
}

// checkInitialized probes storageDir() for an existing root key. Returns
// the directory where the root key was found, or empty string if not
// initialized. This method is safe to call without holding s.mu as it
// performs read-only filesystem operations.
func (s *BarrierService) checkInitialized() string {
	dir := s.storageDir()
	if s.probeRootKey(dir) {
		return dir
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
	defer func() {
		if closeErr := base.Close(); closeErr != nil {
			s.log.Warn("barrier: failed to close base backend after root key probe", "dir", dir, "error", closeErr)
		}
	}()

	exists, err := base.Exists(context.Background(), barrierRootKeyPath)
	if err != nil {
		return false
	}
	return exists
}

// assembleStrategy builds the single sealing strategy matching strategyID.
// No fallback strategies are included — if the selected strategy is
// unavailable, the caller must surface the error.
func (s *BarrierService) assembleStrategy(strategyID string) (xkms.SealingStrategy, error) {
	switch xkms.StrategyID(strategyID) {
	case xkms.StrategyTPM2:
		if s.tpmSealerFn == nil {
			return nil, &ErrBarrierStrategyUnavailable{Strategy: strategyID}
		}
		sealer := s.tpmSealerFn()
		if sealer == nil || !sealer.CanSeal() {
			return nil, &ErrBarrierStrategyUnavailable{Strategy: strategyID}
		}
		return xkms.NewTPM2Strategy(sealer, nil), nil
	case xkms.StrategyPassphrase:
		return xkms.NewSoftwareSealStrategy(), nil
	case xkms.StrategyPKCS11, xkms.StrategyAWSKMS, xkms.StrategyGCPKMS, xkms.StrategyAzureKV, xkms.StrategyVault:
		if s.externalStrategyFn == nil {
			return nil, &ErrBarrierStrategyUnavailable{Strategy: strategyID}
		}
		strategy, err := s.externalStrategyFn(strategyID)
		if err != nil {
			return nil, err
		}
		if strategy == nil {
			return nil, &ErrBarrierStrategyUnavailable{Strategy: strategyID}
		}
		return strategy, nil
	default:
		return nil, &ErrBarrierStrategyUnavailable{Strategy: strategyID}
	}
}

// createBaseBackend creates the base storage backend for the barrier.
// Uses the registered factory if set, otherwise defaults to the go-qrdb file
// engine, which stores each key under a hashed path inside storageDir.
func (s *BarrierService) createBaseBackend(storageDir string) (xkms.StorageBackend, error) {
	if s.baseBackendFn != nil {
		return s.baseBackendFn(storageDir)
	}
	return xkms.StorageOpenEngine(xkms.StorageEngineConfig{Kind: xkms.StorageEngineFile, Path: storageDir})
}

// BarrierSealInfo describes the barrier's seal state for the frontend.
type BarrierSealInfo struct {
	Initialized    bool   `json:"initialized"`
	Sealed         bool   `json:"sealed"`
	Strategy       string `json:"strategy"`
	StrategyLabel  string `json:"strategy_label"`
	HardwareBacked bool   `json:"hardware_backed"`
	// DataDir is the directory of the go-qrdb file engine holding the barrier.
	DataDir string `json:"data_dir"`
	// RootKeyEntry is the engine entry that holds the sealed root key; it is
	// not a file below DataDir.
	RootKeyEntry string `json:"root_key_entry"`
}

// GetSealInfo returns a snapshot of the barrier's seal state for display
// on the Sealed Data page. It checks whether the barrier directory and
// root key exist (initialized), whether the barrier is sealed or unsealed,
// and what strategy is active.
func (s *BarrierService) GetSealInfo() *BarrierSealInfo {
	s.mu.Lock()
	defer s.mu.Unlock()

	foundDir := s.checkInitialized()

	info := &BarrierSealInfo{
		DataDir:      s.storageDir(),
		RootKeyEntry: barrierRootKeyPath,
	}

	if foundDir != "" {
		info.Initialized = true
		// Report the data directory the barrier was actually found in.
		info.DataDir = foundDir
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
			sid := xkms.StrategyID(s.lastStrategy)
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
	// The seal layer no longer exposes an implicit DefaultPreferenceOrder.
	// This GUI helper recommends an available HARDWARE-backed strategy first,
	// otherwise the first available passphrase strategy — derived from each
	// strategy's own HardwareBacked metadata, not a library default.
	probed := s.probeStrategiesUnlocked()
	var fallback *BarrierStrategyInfo
	for i := range probed {
		if !probed[i].Available {
			continue
		}
		if probed[i].HardwareBacked {
			return &probed[i], nil
		}
		if fallback == nil {
			fallback = &probed[i]
		}
	}
	if fallback != nil {
		return fallback, nil
	}
	return nil, xkms.ErrNoAvailableSealStrategy
}

// probeStrategiesUnlocked is the non-locking version of ProbeStrategies.
func (s *BarrierService) probeStrategiesUnlocked() []BarrierStrategyInfo {
	strategies := []BarrierStrategyInfo{
		{
			ID:             string(xkms.StrategyPassphrase),
			Available:      true,
			HardwareBacked: false,
			Label:          strategyLabels[xkms.StrategyPassphrase],
		},
	}
	if s.tpmSealerFn != nil {
		sealer := s.tpmSealerFn()
		// Check both non-nil AND CanSeal() to match the inner barrier's
		// TPM2Strategy.Available() check. Without CanSeal(), the service
		// may report TPM2 as "best" (skipping password guard) while the
		// barrier internally falls to Passphrase with an empty password.
		available := sealer != nil && sealer.CanSeal()
		strategies = append(strategies, BarrierStrategyInfo{
			ID:             string(xkms.StrategyTPM2),
			Available:      available,
			HardwareBacked: true,
			Label:          strategyLabels[xkms.StrategyTPM2],
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
