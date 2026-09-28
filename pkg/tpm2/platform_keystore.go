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

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/pintpm2"
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

	// ErrPlatformSRKHierarchyAuth is returned when the TPM rejects an SRK
	// operation because the owner hierarchy has an authorization value the
	// caller did not supply.
	//
	// The common case is a TPM whose owner hierarchy was given an auth value by
	// ProvisionOwner, followed by an enrollment that supplies a different value
	// or none at all. Creating the persistent Platform SRK and evicting an old
	// one are both owner-hierarchy operations, so both need that auth. The TPM
	// reports only TPM_RC_BAD_AUTH, which names neither the hierarchy nor the
	// mismatch, so this wraps it with both.
	ErrPlatformSRKHierarchyAuth = errors.New("tpm2: owner hierarchy rejected the SRK operation: the hierarchy has an authorization value that was not supplied (pass it as the soPIN argument to EnrollPlatformSRK/Initialize, or clear the TPM)")

	// ErrPlatformSRKAlreadyEnrolled is returned by EnrollPlatformSRK when the
	// Platform SRK auth is already in a known-good state (IsAuthReady), so a
	// first-boot enrollment must not run again.
	ErrPlatformSRKAlreadyEnrolled = errors.New("tpm2: platform SRK already enrolled")

	// ErrPlatformSRKEnrollEmptyPIN is returned by EnrollPlatformSRK when the
	// supplied user PIN is empty. First-boot enrollment must bind a real PIN.
	ErrPlatformSRKEnrollEmptyPIN = errors.New("tpm2: platform SRK enrollment requires a non-empty user PIN")
)

// tpmRCNVDefined is TPM_RC_NV_DEFINED (0x14c), indicating the persistent
// handle is already occupied. Used to detect a prior provisioning attempt
// where the SRK already exists.
var tpmRCNVDefined = tpm2.TPMRC(0x14c)

// PlatformKeyStore provides TPM-backed key storage with integrated PIN management.
// It implements pin.PlatformAuthProvider so the pintpm2.TPM2Backend can delegate
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
	pinBackend  *pintpm2.TPM2Backend
	srkAttrs    *types.KeyAttributes
	initialized atomic.Bool
	authReady   atomic.Bool
}

// Compile-time interface check: PlatformKeyStore implements PlatformAuthProvider.
var _ pintpm2.PlatformAuthProvider = (*PlatformKeyStore)(nil)

// NewPlatformKeyStore creates a new PlatformKeyStore with integrated TPM PIN
// management. The PlatformKeyStore itself serves as the PlatformAuthProvider
// for the pintpm2.TPM2Backend, delegating PIN verification to the PlatformSRK's
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
	srkAttrs, err := PlatformSRKAttributesFromConfig(config)
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
	pks.pinBackend = pintpm2.NewTPM2Backend(pks)

	// Probe the TPM for a previously created SRK to determine initialization
	// state. Note: initialized means "SRK exists", NOT "auth is in a known
	// good state." Callers that need auth confirmation must check
	// IsAuthReady(); a persisted PIN strategy is not a substitute, because it
	// records which backend was selected before rather than that the auth
	// value has been checked.
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
// backend.
//
// soPIN is the TPM owner hierarchy authorization value. The Platform SRK is a
// persistent object in the owner hierarchy, so creating it -- and evicting a
// stale one -- requires that auth whenever ProvisionOwner installed one. It is
// NOT a PKCS#11-style security-officer PIN: the TPM2 PIN backend has no such
// concept and ignores the value. When soPIN is empty the hierarchy auth
// configured for the Platform SRK (config.PlatformSRK.HierarchyAuth) is used
// unchanged; the Shared SRK's own hierarchy auth is never consulted here.
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
	userAuth, err := store.NewPassword([]byte(userPIN))
	if err != nil {
		return err
	}
	srkAttrs.Password = userAuth
	// Creating a persistent SRK is an owner-hierarchy operation, so it needs the
	// owner hierarchy's auth when one is set. ensureSRKAuth already applies the
	// SO PIN this way on its evict/recreate path; this path did not, so a
	// caller supplying an SO PIN still hit TPM_RC_BAD_AUTH on a TPM whose owner
	// hierarchy ProvisionOwner had given an auth value.
	if soPIN != "" {
		soAuth, err := store.NewPassword([]byte(soPIN))
		if err != nil {
			return err
		}
		srkAttrs.TPMAttributes.HierarchyAuth = soAuth
	}
	if err := pks.tpm.CreateSRK(&srkAttrs); err != nil {
		// TPM_RC_NV_DEFINED (0x14c) means the persistent handle is already
		// occupied - the SRK exists from a prior provisioning attempt.
		// Treat this as success but ensure auth matches below.
		if errors.Is(err, tpmRCNVDefined) {
			pks.logger.Info("platform SRK already exists at persistent handle")
			pks.initialized.Store(true)
			return pks.ensureSRKAuth(soPIN, userPIN)
		}
		if isTPMAuthError(err) {
			pks.logger.Error("platform SRK creation rejected by the owner hierarchy",
				slog.Bool("so_pin_supplied", soPIN != ""),
				slog.String("error", err.Error()))
			return errors.Join(ErrPlatformSRKHierarchyAuth, err)
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

// EnrollPlatformSRK performs a deliberate one-shot first-boot enrollment of the
// Platform SRK, binding the operator-supplied userPIN as its authorization
// value so the TPM2 PIN backend works end-to-end on subsequent boots.
//
// soPIN is the TPM owner hierarchy authorization value, the same argument
// Initialize takes. Enrollment creates a persistent object in the owner
// hierarchy, so a TPM whose hierarchy ProvisionOwner gave an auth value can
// only be enrolled by a caller that supplies it; without it the TPM answers
// TPM_RC_BAD_AUTH and enrollment reports ErrPlatformSRKHierarchyAuth. Callers
// whose owner hierarchy has no auth value pass an empty string, which leaves
// the hierarchy auth configured for the SRK in force.
//
// It is idempotent: when the SRK auth is already in a known-good state
// (IsAuthReady), it returns ErrPlatformSRKAlreadyEnrolled so a daemon can skip
// enrollment on every boot after the first without treating it as a failure.
// An empty userPIN is rejected with ErrPlatformSRKEnrollEmptyPIN.
//
// Enrollment reuses the existing Initialize/ensureSRKAuth machinery; it adds no
// new TPM primitives.
func (pks *PlatformKeyStore) EnrollPlatformSRK(soPIN, userPIN string) error {
	if userPIN == "" {
		return ErrPlatformSRKEnrollEmptyPIN
	}
	if pks.IsAuthReady() {
		return ErrPlatformSRKAlreadyEnrolled
	}
	if err := pks.Initialize(soPIN, userPIN); err != nil {
		return err
	}
	pks.logger.Info("platform SRK enrolled at first boot")
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
		soAuth, err := store.NewPassword([]byte(soPIN))
		if err != nil {
			return err
		}
		evictAttrs.TPMAttributes.HierarchyAuth = soAuth
	}
	name, _, readErr := pks.tpm.ReadHandle(evictAttrs.TPMAttributes.Handle)
	if readErr != nil {
		pks.authReady.Store(false)
		return errors.Join(ErrPlatformKeyStoreEvictSRK, readErr)
	}
	evictAttrs.TPMAttributes.Name = name
	if err := pks.tpm.DeleteKey(&evictAttrs, pks.backend); err != nil {
		pks.logger.Error("failed to evict platform SRK",
			slog.Bool("so_pin_supplied", soPIN != ""),
			slog.String("error", err.Error()),
			slog.String("hint", "clear the TPM or provide the correct SO PIN"))
		pks.authReady.Store(false)
		if isTPMAuthError(err) {
			return errors.Join(ErrPlatformSRKHierarchyAuth, err)
		}
		return errors.Join(ErrPlatformKeyStoreEvictSRK, err)
	}

	srkAttrs := *pks.srkAttrs
	userAuth, err := store.NewPassword([]byte(userPIN))
	if err != nil {
		return err
	}
	srkAttrs.Password = userAuth
	if soPIN != "" {
		soAuth, err := store.NewPassword([]byte(soPIN))
		if err != nil {
			return err
		}
		srkAttrs.TPMAttributes.HierarchyAuth = soAuth
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
	emptyAuth, err := store.NewPassword(nil)
	if err != nil {
		return err
	}
	srkAttrs.Password = emptyAuth
	if err := pks.tpm.CreateSRK(&srkAttrs); err != nil {
		// TPM_RC_NV_DEFINED (0x14c) means the persistent handle is already
		// occupied - the SRK exists from a prior provisioning attempt.
		// Mark initialized (SRK exists) but NOT authReady — auth state is
		// unknown. The app layer decides via persisted PINStrategy config.
		if errors.Is(err, tpmRCNVDefined) {
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

// PINBackend returns the PIN backend for this key store.
func (pks *PlatformKeyStore) PINBackend() qrdbsdk.PINBackend {
	return pks.pinBackend
}

// PlatformPolicyEnabled returns true if TPM platform policy is enabled in
// the key store configuration.
func (pks *PlatformKeyStore) PlatformPolicyEnabled() bool {
	return platformPolicyEnabled(pks.config)
}

// platformPolicyEnabled reports whether the Platform SRK is platform-bound.
// It is the single reading of that setting: the Platform SRK's attributes and
// every predicate that reports on them must agree, and the SSRK configuration
// has no say in it.
func platformPolicyEnabled(config *Config) bool {
	return config != nil && config.PlatformSRK != nil && config.PlatformSRK.PlatformPolicy
}

// VerifyAuth verifies the user PIN against the PlatformSRK's password auth.
// Uses TPM2_Create as a parent auth check: creating a minimal child object
// under the SRK succeeds only when the correct auth value is provided.
//
// Only a genuine authorization failure (a wrong PIN) is reported as
// ErrAuthFailed. Any other TPM fault (e.g. a malformed probe surfacing as
// TPM_RC_ATTRIBUTES, a missing handle, or a transport error) is returned
// verbatim so it is NOT misreported as an invalid PIN — masking such errors
// previously hid the invalid auth-probe template bug.
func (pks *PlatformKeyStore) VerifyAuth(userPIN string) error {
	if !pks.initialized.Load() {
		return ErrPlatformKeyStoreNotInitialized
	}
	if pks.srkAttrs.TPMAttributes == nil {
		return ErrPlatformKeyStoreNoSRKHandle
	}

	err := pks.tpm.VerifyAuth(pks.srkAttrs.TPMAttributes.Handle, []byte(userPIN))
	if err == nil {
		// The SRK accepted this auth value, which is the definition of the
		// auth being in a known-good state. Recording it here means a PIN
		// backend built later in the process reports the credential as
		// known rather than regressing to "unset" and refusing to check it.
		pks.authReady.Store(true)
		return nil
	}
	if errors.Is(err, ErrAuthFailed) || isTPMAuthError(err) {
		return ErrAuthFailed
	}
	return err
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

	if err := pks.tpm.ChangeAuth(
		pks.srkAttrs.TPMAttributes.Handle,
		[]byte(currentPIN),
		[]byte(newPIN),
	); err != nil {
		// The verification above marked the auth known-good, but changing it
		// evicts the persistent SRK before recreating and re-persisting it.
		// A failure part-way can leave no key at the expected handle, so what
		// the SRK now holds is unknown and must not keep reporting ready:
		// callers use that flag to skip enrollment and to decide a credential
		// exists to check against.
		pks.authReady.Store(false)
		// The same failure decides whether an SRK exists at all. Re-probe the
		// handle and let IsProvisioned report what is actually there, so a
		// retry through Initialize takes the clean-recreate branch when the
		// key is gone instead of ensureSRKAuth, which assumes an SRK to
		// verify against and fails at ReadHandle (#448). Recovery itself is
		// left to that retry: this path reports, it does not re-provision.
		pks.reconcileSRKPresence()
		return err
	}

	// The new auth value is the one this application just installed, so the
	// auth is in a known-good state.
	pks.authReady.Store(true)
	return nil
}

// reconcileSRKPresence sets initialized from whether the persistent SRK
// handle currently holds an object, refreshing the cached Name when it does.
// It is the same probe the constructor runs, applied after an operation that
// may have evicted the key.
func (pks *PlatformKeyStore) reconcileSRKPresence() {
	handle := pks.srkAttrs.TPMAttributes.Handle
	srkName, _, err := pks.tpm.ReadHandle(handle)
	if err != nil {
		pks.logger.Warn("platform SRK is no longer present after a failed auth change; the store is unprovisioned until Initialize recreates it",
			slog.Uint64("handle", uint64(handle)),
			slog.String("error", err.Error()))
		pks.initialized.Store(false)
		return
	}
	pks.srkAttrs.TPMAttributes.Name = srkName
	pks.initialized.Store(true)
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

// SetAuthReady explicitly sets the auth-ready state, for a caller that has
// confirmed the SRK's auth value by other means. Persisted configuration is
// not such a means: a recorded PIN strategy says which backend was selected
// before, not that this session checked the auth. VerifyAuth and ChangeAuth
// set this themselves on success, and a failed ChangeAuth clears it.
func (pks *PlatformKeyStore) SetAuthReady(ready bool) {
	pks.authReady.Store(ready)
}

// platformSRKHandle returns the persistent handle of the Platform SRK:
// PlatformSRKConfig.SRKHandle when set, otherwise the default tpSRKIndex
// (0x81000002).
func platformSRKHandle(config *Config) tpm2.TPMHandle {
	if config != nil && config.PlatformSRK != nil && config.PlatformSRK.SRKHandle != 0 {
		return tpm2.TPMHandle(config.PlatformSRK.SRKHandle)
	}
	return tpm2.TPMHandle(tpSRKIndex)
}

// PlatformSRKAttributesFromConfig creates Platform SRK key attributes from
// the TPM Config. It uses the PlatformSRKConfig.SRKHandle if set, otherwise
// falls back to the default tpSRKIndex (0x81000002).
//
// TPMAttributes.HierarchyAuth is always left unset (empty), matching the TCG
// factory-default owner-hierarchy state. PlatformSRKConfig carries no
// hierarchy-auth field on purpose: the Security Officer PIN needed to
// authorize TPM2_CreatePrimary/EvictControl when an operator has set one is
// never stored in configuration. A caller that knows the live owner
// hierarchy auth supplies it at the moment of the operation -- the soPIN
// argument to Initialize/EnrollPlatformSRK/ensureSRKAuth -- overwriting the
// zero value this function returns.
//
// The Platform SRK is the object whose authorization value IS the user PIN.
// For failed PIN guesses to trip the TPM's dictionary-attack (DA) protection,
// this object MUST have its NoDA attribute cleared: the standard SRK templates
// set NoDA=true (appropriate for a generic storage parent that is never the
// auth target), which leaves PIN brute-forcing unthrottled despite the lockout
// plumbing. Clearing NoDA on the PIN-verification SRK — and only on it; the
// seal SSRK at a different handle is unaffected — makes each wrong PIN
// increment the DA counter toward hardware lockout while a correct PIN still
// authorizes normally.
//
// The SSRK configuration supplies nothing but algorithm and key parameters --
// never its own HierarchyAuth. Whether the Platform SRK is platform-bound is
// decided by PlatformSRKConfig.PlatformPolicy and nowhere else — the SSRK
// cannot express a platform policy at all, and could not lend one to a key
// it is not.
func PlatformSRKAttributesFromConfig(config *Config) (*types.KeyAttributes, error) {
	srkHandle := uint32(platformSRKHandle(config))

	platformPolicy := platformPolicyEnabled(config)

	// Use SSRK config if available for algorithm/key parameters only. Its own
	// HierarchyAuth is cleared before use so SRKAttributesFromConfig cannot
	// carry it into the Platform SRK's attributes: HierarchyAuth is always
	// left at its empty zero value here, per the TCG factory default.
	if config.SSRK != nil {
		cfg := *config.SSRK
		cfg.Handle = srkHandle
		cfg.HierarchyAuth = nil
		attrs, err := SRKAttributesFromConfig(cfg)
		if err != nil {
			return nil, err
		}
		attrs.PlatformPolicy = platformPolicy
		enableDAOnSRK(attrs)
		return attrs, nil
	}

	// Minimal SRK attributes from keystore config
	attrs := &types.KeyAttributes{
		CN:             "srk",
		KeyType:        types.KeyTypeStorage,
		PlatformPolicy: platformPolicy,
		StoreType:      types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			Handle:     tpm2.TPMHandle(srkHandle),
			HandleType: tpm2.TPMHTPersistent,
			Hierarchy:  tpm2.TPMHandle(tpm2.TPMRHOwner),
			Template:   rsaSRKTemplateWithDA(),
		},
	}
	return attrs, nil
}

// rsaSRKTemplateWithDA returns the RSA SRK template with DA protection enabled
// (NoDA cleared) so that authorization failures against the PIN SRK increment
// the TPM dictionary-attack counter.
func rsaSRKTemplateWithDA() tpm2.TPMTPublic {
	tmpl := tpm2.RSASRKTemplate
	tmpl.ObjectAttributes.NoDA = false
	return tmpl
}

// enableDAOnSRK clears the NoDA attribute on the SRK template so wrong-PIN
// authorization failures trip TPM dictionary-attack protection.
func enableDAOnSRK(attrs *types.KeyAttributes) {
	if attrs == nil || attrs.TPMAttributes == nil {
		return
	}
	attrs.TPMAttributes.Template.ObjectAttributes.NoDA = false
}
