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

package tpm2

import (
	"errors"
	"log/slog"
	"sync/atomic"

	"github.com/google/go-tpm/tpm2"

	"github.com/jeremyhahn/go-xkms/pkg/pin"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Compile-time interface check.
var _ PlatformKeyStorer = (*PlatformKeyStore)(nil)

var (
	// ErrPlatformKeyStoreNilTPM is returned when the TPM parameter is nil.
	ErrPlatformKeyStoreNilTPM = errors.New("tpm2: platform key store requires a non-nil TPM")

	// ErrPlatformKeyStoreNilBackend is returned when the backend parameter is nil.
	ErrPlatformKeyStoreNilBackend = errors.New("tpm2: platform key store requires a non-nil backend")

	// ErrPlatformKeyStoreNilConfig is returned when the config parameter is nil.
	ErrPlatformKeyStoreNilConfig = errors.New("tpm2: platform key store requires a non-nil config")

	// ErrPlatformKeyStoreAlreadyInitialized is returned when Initialize is
	// called on an already initialized store.
	ErrPlatformKeyStoreAlreadyInitialized = errors.New("tpm2: platform key store already initialized")

	// ErrPlatformKeyStoreSetSOPIN is returned when the SO PIN cannot be set.
	ErrPlatformKeyStoreSetSOPIN = errors.New("tpm2: platform key store failed to set SO PIN")

	// ErrPlatformKeyStoreSetUserPIN is returned when the user PIN cannot be set.
	ErrPlatformKeyStoreSetUserPIN = errors.New("tpm2: platform key store failed to set user PIN")

	// ErrPlatformKeyStoreCreateSRK is returned when the SRK cannot be created.
	ErrPlatformKeyStoreCreateSRK = errors.New("tpm2: platform key store failed to create SRK")

	// ErrPlatformKeyStoreSRKConfig is returned when the SRK attributes
	// cannot be derived from config.
	ErrPlatformKeyStoreSRKConfig = errors.New("tpm2: platform key store failed to build SRK attributes from config")

	// ErrPlatformKeyStorePINManager is returned when the PIN manager cannot
	// be created.
	ErrPlatformKeyStorePINManager = errors.New("tpm2: platform key store failed to create PIN manager")

	// ErrPlatformKeyStoreNotInitialized is returned when VerifyAuth or
	// ChangeAuth is called before the key store has been initialized.
	ErrPlatformKeyStoreNotInitialized = errors.New("tpm2: platform key store not initialized")

	// ErrPlatformKeyStoreNoSRKHandle is returned when the SRK attributes
	// do not contain a valid TPM handle.
	ErrPlatformKeyStoreNoSRKHandle = errors.New("tpm2: platform key store SRK has no TPM handle")

	// ErrPlatformKeyStoreEvictSRK is returned when the existing Platform
	// SRK cannot be evicted. This typically happens when the TPM owner
	// hierarchy has auth from a prior installation that is unknown.
	ErrPlatformKeyStoreEvictSRK = errors.New("tpm2: platform key store failed to evict existing SRK (owner hierarchy auth unknown; clear TPM or provide correct SO PIN)")
)

// tpmRCNVDefined is TPM_RC_NV_DEFINED (0x14c), indicating the persistent
// handle is already occupied. Used to detect a prior provisioning attempt
// where the SRK already exists.
var tpmRCNVDefined = tpm2.TPMRC(0x14c)

// PlatformKeyStore provides TPM-backed key storage with integrated PIN management.
// It implements pin.PlatformAuthProvider so the pin.TPM2Backend can delegate
// all PIN verification to the PlatformSRK's password auth.
//
// The Platform SRK (at tpSRKIndex = 0x81000002) is the only key used for PIN
// verification. If the Platform SRK cannot be provisioned (e.g., because the
// TPM owner hierarchy has auth from a prior installation), initialization fails
// with a clear error directing the user to clear the TPM or provide the correct
// SO PIN.
type PlatformKeyStore struct {
	logger      *slog.Logger
	tpm         TrustedPlatformModule
	backend     store.KeyBackend
	config      *Config
	pinBackend  *pin.TPM2Backend
	srkAttrs    *types.KeyAttributes
	initialized atomic.Bool
	authReady   atomic.Bool
}

// Compile-time interface check: PlatformKeyStore implements PlatformAuthProvider.
var _ pin.PlatformAuthProvider = (*PlatformKeyStore)(nil)

// NewPlatformKeyStore creates a new PlatformKeyStore with integrated TPM PIN
// management. The PlatformKeyStore itself serves as the PlatformAuthProvider
// for the pin.TPM2Backend, delegating PIN verification to the PlatformSRK's
// password auth value.
func NewPlatformKeyStore(
	logger *slog.Logger,
	tpm TrustedPlatformModule,
	backend store.KeyBackend,
	config *Config,
	pinStatePath string,
) (*PlatformKeyStore, error) {

	if tpm == nil {
		return nil, ErrPlatformKeyStoreNilTPM
	}
	if backend == nil {
		return nil, ErrPlatformKeyStoreNilBackend
	}
	if config == nil {
		return nil, ErrPlatformKeyStoreNilConfig
	}

	// Build SRK attributes from platform SRK config
	srkAttrs, err := buildSRKAttrsFromConfig(config)
	if err != nil {
		return nil, errors.Join(ErrPlatformKeyStoreSRKConfig, err)
	}

	pks := &PlatformKeyStore{
		logger:   logger,
		tpm:      tpm,
		backend:  backend,
		config:   config,
		srkAttrs: srkAttrs,
	}

	// Create the PIN backend using the PlatformKeyStore itself as provider.
	// The TPM2Backend delegates PIN verification to PlatformSRK password auth.
	pks.pinBackend = pin.NewTPM2Backend(pks)

	// Probe the TPM for a previously created SRK to determine initialization
	// state. Note: initialized means "SRK exists", NOT "auth is in a known
	// good state." Callers that need auth confirmation must check IsAuthReady()
	// or use the persisted PIN strategy from the app config.
	//
	// When the SRK exists, populate its Name via TPM2_ReadPublic so that
	// downstream TPM2_Load calls have a valid ParentHandle Name. Without this,
	// after an app restart the cached srkAttrs only contain the persistent
	// handle (from config) and TPM2_Load fails with "missing Name for
	// 'ParentHandle' parameter".
	if srkAttrs.TPMAttributes != nil {
		srkName, _, err := tpm.ReadHandle(srkAttrs.TPMAttributes.Handle)
		if err == nil {
			srkAttrs.TPMAttributes.Name = srkName
			pks.initialized.Store(true)
		}
	}

	return pks, nil
}

// Initialize sets up the platform key store by creating the Storage Root Key
// (SRK) with the user PIN as its auth value, then registering the PIN in the
// backend. The soPIN parameter is accepted for backward compatibility but
// is not used by the TPM2 PIN backend (TPM has no separate SO PIN concept).
//
// If the SRK already exists (from a prior session or auto-initialization),
// Initialize ensures its auth value matches userPIN. This handles the case
// where the setup wizard is re-run after a partial setup left the SRK with
// empty auth.
func (pks *PlatformKeyStore) Initialize(soPIN, userPIN string) error {
	if pks.initialized.Load() {
		return pks.ensureSRKAuth(soPIN, userPIN)
	}

	// Create SRK first with user PIN as auth value. The SRK must exist
	// before the TPM2Backend can verify PINs against it.
	srkAttrs := *pks.srkAttrs
	srkAttrs.Password = store.NewPassword([]byte(userPIN))
	if pks.PlatformPolicyEnabled() {
		srkAttrs.PlatformPolicy = true
	}
	if err := pks.tpm.CreateSRK(&srkAttrs); err != nil {
		// TPM_RC_NV_DEFINED (0x14c) means the persistent handle is already
		// occupied - the SRK exists from a prior provisioning attempt.
		// Treat this as success but ensure auth matches below.
		if err == tpmRCNVDefined {
			pks.logger.Info("platform SRK already exists at persistent handle")
			pks.initialized.Store(true)
			return pks.ensureSRKAuth(soPIN, userPIN)
		}
		return errors.Join(ErrPlatformKeyStoreCreateSRK, err)
	}

	// Update cached attributes with data enriched by CreateSRK.
	*pks.srkAttrs = srkAttrs

	pks.initialized.Store(true)

	// Register the user PIN in the backend. For TPM2Backend this verifies
	// the PIN against the newly created SRK and caches the FIDO2 hash.
	// The soPIN parameter is ignored by TPM2Backend.
	if err := pks.pinBackend.SetUserPIN(soPIN, userPIN); err != nil {
		return errors.Join(ErrPlatformKeyStoreSetUserPIN, err)
	}

	// Auth is synchronized: we just created the SRK with userPIN as auth.
	pks.authReady.Store(true)

	pks.logger.Info("platform key store initialized",
		slog.Bool("platform_policy", pks.PlatformPolicyEnabled()))

	return nil
}

// ensureSRKAuth ensures PIN verification will work with the provided userPIN.
//
// Strategy (in order of preference):
//  1. If the SRK's auth already matches userPIN, register and return.
//  2. Evict the old SRK and recreate it with userPIN auth.
//
// If eviction fails (e.g., TPM owner hierarchy has auth from a prior
// installation), the error is returned so the caller can inform the user
// to clear the TPM or provide the correct SO PIN.
func (pks *PlatformKeyStore) ensureSRKAuth(soPIN, userPIN string) error {
	// Fast path: auth already matches.
	if err := pks.VerifyAuth(userPIN); err == nil {
		pks.logger.Info("platform SRK auth already matches user PIN")
		if setErr := pks.pinBackend.SetUserPIN(soPIN, userPIN); setErr != nil {
			return errors.Join(ErrPlatformKeyStoreSetUserPIN, setErr)
		}
		pks.authReady.Store(true)
		return nil
	}

	// Evict the old SRK and recreate it with the correct auth.
	pks.logger.Info("platform SRK auth mismatch, evicting and recreating")

	evictAttrs := *pks.srkAttrs
	if soPIN != "" {
		evictAttrs.TPMAttributes.HierarchyAuth = store.NewPassword([]byte(soPIN))
	}
	name, _, readErr := pks.tpm.ReadHandle(evictAttrs.TPMAttributes.Handle)
	if readErr != nil {
		pks.authReady.Store(false)
		return errors.Join(ErrPlatformKeyStoreEvictSRK, readErr)
	}
	evictAttrs.TPMAttributes.Name = name
	if err := pks.tpm.DeleteKey(&evictAttrs, pks.backend); err != nil {
		pks.logger.Error("failed to evict platform SRK",
			slog.String("error", err.Error()),
			slog.String("hint", "clear the TPM or provide the correct SO PIN"))
		pks.authReady.Store(false)
		return errors.Join(ErrPlatformKeyStoreEvictSRK, err)
	}

	srkAttrs := *pks.srkAttrs
	srkAttrs.Password = store.NewPassword([]byte(userPIN))
	if soPIN != "" {
		srkAttrs.TPMAttributes.HierarchyAuth = store.NewPassword([]byte(soPIN))
	}
	if pks.PlatformPolicyEnabled() {
		srkAttrs.PlatformPolicy = true
	}
	if err := pks.tpm.CreateSRK(&srkAttrs); err != nil {
		return errors.Join(ErrPlatformKeyStoreCreateSRK, err)
	}
	*pks.srkAttrs = srkAttrs

	if err := pks.pinBackend.SetUserPIN(soPIN, userPIN); err != nil {
		return errors.Join(ErrPlatformKeyStoreSetUserPIN, err)
	}
	pks.authReady.Store(true)
	pks.logger.Info("platform SRK recreated with user PIN auth")
	return nil
}

// InitializeWithDefaults creates the Platform SRK using empty (default) TPM
// hierarchy auth. This is used when the user chose not to set TPM hierarchy
// authorization passwords. It skips PINManager setup entirely and creates
// the SRK with no auth value.
func (pks *PlatformKeyStore) InitializeWithDefaults() error {
	if pks.initialized.Load() {
		return ErrPlatformKeyStoreAlreadyInitialized
	}

	// Create SRK with empty auth (TPM default).
	srkAttrs := *pks.srkAttrs
	srkAttrs.Password = store.NewPassword(nil)
	if pks.PlatformPolicyEnabled() {
		srkAttrs.PlatformPolicy = true
	}
	if err := pks.tpm.CreateSRK(&srkAttrs); err != nil {
		// TPM_RC_NV_DEFINED (0x14c) means the persistent handle is already
		// occupied - the SRK exists from a prior provisioning attempt.
		// Mark initialized (SRK exists) but NOT authReady — auth state is
		// unknown. The app layer decides via persisted PINStrategy config.
		if err == tpmRCNVDefined {
			pks.logger.Info("platform SRK already exists at persistent handle")
			pks.initialized.Store(true)
			pks.logger.Info("platform key store initialized with defaults (existing SRK)",
				slog.Bool("platform_policy", pks.PlatformPolicyEnabled()))
			return nil
		}
		return errors.Join(ErrPlatformKeyStoreCreateSRK, err)
	}

	// Update cached attributes with data enriched by CreateSRK
	// (public key, algorithm, TPM attributes, etc.).
	*pks.srkAttrs = srkAttrs

	pks.initialized.Store(true)

	// We just created the SRK with empty auth — auth state is known.
	pks.authReady.Store(true)

	pks.logger.Info("platform key store initialized with defaults",
		slog.Bool("platform_policy", pks.PlatformPolicyEnabled()))

	return nil
}

// SRKAttributes returns the Storage Root Key attributes.
func (pks *PlatformKeyStore) SRKAttributes() *types.KeyAttributes {
	return pks.srkAttrs
}

// Backend returns the key backend used by this store.
func (pks *PlatformKeyStore) Backend() store.KeyBackend {
	return pks.backend
}

// IsInitialized returns true if the platform key store has been initialized
// with PINs and SRK.
func (pks *PlatformKeyStore) IsInitialized() bool {
	return pks.initialized.Load()
}

// PINManager returns the integrated PIN manager for backward compatibility.
// New code should use PINBackend() instead.
//
// Deprecated: Use PINBackend() instead.
func (pks *PlatformKeyStore) PINManager() pin.PINManager { //nolint:staticcheck // TODO: migrate to PINBackend
	return &pin.PINManagerAdapter{PINBackend: pks.pinBackend} //nolint:staticcheck // TODO: migrate to PINBackend
}

// PINBackend returns the modern PIN backend for this key store.
func (pks *PlatformKeyStore) PINBackend() pin.PINBackend {
	return pks.pinBackend
}

// PlatformPolicyEnabled returns true if TPM platform policy is enabled in
// the key store configuration.
func (pks *PlatformKeyStore) PlatformPolicyEnabled() bool {
	if pks.config.PlatformSRK == nil {
		return false
	}
	return pks.config.PlatformSRK.PlatformPolicy
}

// VerifyAuth verifies the user PIN against the PlatformSRK's password auth.
// Uses TPM2_Create as a parent auth check: creating a minimal child object
// under the SRK succeeds only when the correct auth value is provided.
func (pks *PlatformKeyStore) VerifyAuth(userPIN string) error {
	if !pks.initialized.Load() {
		return ErrPlatformKeyStoreNotInitialized
	}
	if pks.srkAttrs.TPMAttributes == nil {
		return ErrPlatformKeyStoreNoSRKHandle
	}

	if err := pks.tpm.VerifyAuth(pks.srkAttrs.TPMAttributes.Handle, []byte(userPIN)); err != nil {
		return ErrAuthFailed
	}
	return nil
}

// ChangeAuth changes the PlatformSRK's password auth (user PIN change).
func (pks *PlatformKeyStore) ChangeAuth(currentPIN, newPIN string) error {
	if !pks.initialized.Load() {
		return ErrPlatformKeyStoreNotInitialized
	}
	if pks.srkAttrs.TPMAttributes == nil {
		return ErrPlatformKeyStoreNoSRKHandle
	}

	// Verify the current PIN first.
	if err := pks.VerifyAuth(currentPIN); err != nil {
		return err
	}

	return pks.tpm.ChangeAuth(
		pks.srkAttrs.TPMAttributes.Handle,
		[]byte(currentPIN),
		[]byte(newPIN),
	)
}

// GetLockoutInfo returns real TPM dictionary attack lockout counters by
// querying the TPM's fixed properties. Returns failedAttempts, maxFail,
// interval (seconds), and recovery (seconds).
func (pks *PlatformKeyStore) GetLockoutInfo() (failedAttempts, maxFail, interval, recovery int, err error) {
	props, err := pks.tpm.FixedProperties()
	if err != nil || props == nil {
		// Return safe defaults on error so callers can degrade gracefully.
		return 0, 10, 0, 300, err
	}
	return int(props.LockoutCounter),
		int(props.MaxAuthFail),
		int(props.LockoutInterval),
		int(props.LockoutRecovery),
		nil
}

// DictionaryAttackLockoutReset resets the TPM DA lockout counter using
// the lockout authorization value.
func (pks *PlatformKeyStore) DictionaryAttackLockoutReset(lockoutAuth []byte) error {
	return pks.tpm.DictionaryAttackLockoutReset(lockoutAuth)
}

// IsProvisioned returns true if the TPM has been provisioned. Determined by
// checking whether the SRK handle is readable.
func (pks *PlatformKeyStore) IsProvisioned() bool {
	return pks.initialized.Load()
}

// IsAuthReady returns true if the PlatformSRK's auth value is in a known good
// state — either set by this application or confirmed to match via VerifyAuth.
// This is the correct predicate for selecting the TPM2 PIN backend; using
// IsInitialized alone can return true when the SRK exists from a prior TPM
// owner with unknown auth.
func (pks *PlatformKeyStore) IsAuthReady() bool {
	return pks.authReady.Load()
}

// SetAuthReady explicitly sets the auth-ready state. This is called by the
// application layer when restoring a previously confirmed TPM2 PIN backend
// selection from persisted config (e.g., GUIConfig.PINStrategy == "tpm2").
func (pks *PlatformKeyStore) SetAuthReady(ready bool) {
	pks.authReady.Store(ready)
}

// buildSRKAttrsFromConfig creates SRK key attributes from the TPM Config.
// It uses the PlatformSRKConfig.SRKHandle if set, otherwise falls back to the
// default tpSRKIndex (0x81000002).
func buildSRKAttrsFromConfig(config *Config) (*types.KeyAttributes, error) {
	var srkHandle uint32

	if config.PlatformSRK != nil && config.PlatformSRK.SRKHandle != 0 {
		srkHandle = config.PlatformSRK.SRKHandle
	} else {
		srkHandle = tpSRKIndex
	}

	// Use SSRK config if available for algorithm/key parameters
	if config.SSRK != nil {
		cfg := *config.SSRK
		cfg.Handle = srkHandle
		return SRKAttributesFromConfig(cfg, nil)
	}

	// Minimal SRK attributes from keystore config
	return &types.KeyAttributes{
		CN:        "srk",
		KeyType:   types.KeyTypeStorage,
		StoreType: types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			Handle:     tpm2.TPMHandle(srkHandle),
			HandleType: tpm2.TPMHTPersistent,
			Hierarchy:  tpm2.TPMHandle(tpm2.TPMRHOwner),
		},
	}, nil
}
