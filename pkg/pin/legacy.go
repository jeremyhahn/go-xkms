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

package pin

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/argon2"
)

// Legacy Argon2id parameters used by FilePINManager.
const (
	legacyArgon2Time    = 3
	legacyArgon2Memory  = 64 * 1024
	legacyArgon2Threads = 4
	legacyArgon2KeyLen  = 32
	legacyArgon2SaltLen = 16

	legacyStateFilePerms = 0600
	maxBackoffDuration   = time.Hour
)

// TPMProvider abstracts TPM 2.0 operations needed for PIN management,
// avoiding a direct dependency on pkg/tpm2.
//
// Deprecated: Use [PlatformAuthProvider] with [TPM2Backend] instead.
type TPMProvider interface {
	Install(soPIN string) error
	SetHierarchyAuth(hierarchy, oldAuth, newAuth string) error
	GetLockoutInfo() (failedAttempts, maxFail, interval, recovery int, err error)
	DictionaryAttackLockoutReset(lockoutAuth []byte) error
	IsProvisioned() bool
}

// PINState holds the persisted PIN state for legacy file-based managers.
//
// Deprecated: Used by legacy [TPMPINManager] and [FilePINManager]. New code
// should use [PINBackend] implementations directly.
type PINState struct {
	SOPINHash           []byte    `json:"so_pin_hash"`
	SOPINSalt           []byte    `json:"so_pin_salt"`
	SOPINSet            bool      `json:"so_pin_set"`
	SOPINHierarchyBound bool      `json:"so_pin_hierarchy_bound"`
	UserPINHash         []byte    `json:"user_pin_hash"`
	UserPINSalt         []byte    `json:"user_pin_salt"`
	FailedAttempts      int       `json:"failed_attempts"`
	LastFailedAt        time.Time `json:"last_failed_at"`
	LockoutUntil        time.Time `json:"lockout_until"`
	Version             int       `json:"version"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

func legacyLoadState(path string) (*PINState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &PINState{
				Version:   1,
				CreatedAt: time.Now().UTC(),
				UpdatedAt: time.Now().UTC(),
			}, nil
		}
		return nil, err
	}
	var state PINState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, ErrStateCorrupted
	}
	return &state, nil
}

func legacySaveState(path string, state *PINState) error {
	state.UpdatedAt = time.Now().UTC()
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmpFile, err := os.CreateTemp(dir, ".pin-state-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmpFile.Chmod(legacyStateFilePerms); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, path)
}

func legacyHashPIN(pin string) (hash, salt []byte, err error) {
	salt = make([]byte, legacyArgon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, err
	}
	hash = argon2.IDKey([]byte(pin), salt, legacyArgon2Time, legacyArgon2Memory, legacyArgon2Threads, legacyArgon2KeyLen)
	return hash, salt, nil
}

func legacyVerifyPIN(pin string, hash, salt []byte) bool {
	computed := argon2.IDKey([]byte(pin), salt, legacyArgon2Time, legacyArgon2Memory, legacyArgon2Threads, legacyArgon2KeyLen)
	return subtle.ConstantTimeCompare(computed, hash) == 1
}

func copyBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	return cp
}

// Compile-time interface checks for legacy types.
var (
	_ PINManager = (*TPMPINManager)(nil)
	_ PINBackend = (*TPMPINManager)(nil)
	_ PINSeeder  = (*TPMPINManager)(nil)
	_ PINManager = (*FilePINManager)(nil)
	_ PINBackend = (*FilePINManager)(nil)
	_ PINSeeder  = (*FilePINManager)(nil)
)

// TPM hierarchy names used by the legacy TPMPINManager.
const (
	hierarchyEndorsement = "endorsement"
	hierarchyOwner       = "owner"
)

// TPMPINManager implements PINBackend by bridging to TPM 2.0 hierarchy authentication.
//
// Deprecated: Use [NewService] with a [TPM2Backend] instead.
type TPMPINManager struct {
	tpm        TPMProvider
	statePath  string
	lockoutCfg LockoutConfig
	state      atomic.Pointer[PINState]
}

// NewTPMPINManager creates a new TPM-based PIN manager.
//
// Deprecated: Use [NewService] with a [TPM2Backend] instead.
func NewTPMPINManager(tpm TPMProvider, statePath string, lockoutCfg LockoutConfig) (*TPMPINManager, error) {
	state, err := legacyLoadState(statePath)
	if err != nil {
		return nil, err
	}
	mgr := &TPMPINManager{tpm: tpm, statePath: statePath, lockoutCfg: lockoutCfg}
	mgr.state.Store(state)
	return mgr, nil
}

func (m *TPMPINManager) SetMaxAttempts(n int) { m.lockoutCfg.MaxAttempts = n }
func (m *TPMPINManager) Strategy() StrategyID { return StrategyTPM2 }

func (m *TPMPINManager) SetSOPIN(currentSOPIN, newSOPIN string) error {
	if err := validatePINLength(newSOPIN); err != nil {
		return err
	}
	state := m.loadStateCopy()
	if m.tpm.IsProvisioned() {
		if state.SOPINHierarchyBound {
			if currentSOPIN == "" {
				return ErrPINAlreadySet
			}
			if err := m.tpm.SetHierarchyAuth(hierarchyEndorsement, currentSOPIN, newSOPIN); err != nil {
				if isAuthError(err) {
					return ErrInvalidCurrentPIN
				}
				return err
			}
		} else if len(state.SOPINHash) > 0 {
			if currentSOPIN == "" {
				return ErrPINAlreadySet
			}
			if !legacyVerifyPIN(currentSOPIN, state.SOPINHash, state.SOPINSalt) {
				return ErrInvalidCurrentPIN
			}
			// Legacy hash migration: the TPM hierarchy was never password-protected
			// (the PIN was only stored as a local hash). Pass empty string as
			// the current hierarchy auth when upgrading to hierarchy-bound.
			if err := m.tpm.SetHierarchyAuth(hierarchyEndorsement, "", newSOPIN); err != nil {
				return err
			}
		} else {
			if err := m.tpm.SetHierarchyAuth(hierarchyEndorsement, currentSOPIN, newSOPIN); err != nil {
				if isAuthError(err) {
					if retryErr := m.tpm.SetHierarchyAuth(hierarchyEndorsement, newSOPIN, newSOPIN); retryErr != nil {
						if isAuthError(retryErr) {
							return ErrHierarchyAuthMismatch
						}
						return retryErr
					}
				} else {
					return err
				}
			}
		}
	} else {
		if currentSOPIN != "" {
			return ErrPINNotSet
		}
		if err := m.tpm.Install(newSOPIN); err != nil {
			return err
		}
	}
	state.SOPINSet = true
	state.SOPINHierarchyBound = true
	state.SOPINHash = nil
	state.SOPINSalt = nil
	return m.persistState(state)
}

func (m *TPMPINManager) SetUserPIN(soPIN, newUserPIN string) error {
	if err := validatePINLength(newUserPIN); err != nil {
		return err
	}
	state := m.loadStateCopy()
	if !state.SOPINSet && len(state.SOPINHash) == 0 {
		return ErrSOPINRequired
	}
	if state.SOPINHierarchyBound {
		if err := m.tpm.SetHierarchyAuth(hierarchyEndorsement, soPIN, soPIN); err != nil {
			if isAuthError(err) {
				return ErrPINInvalid
			}
			return err
		}
	} else if !legacyVerifyPIN(soPIN, state.SOPINHash, state.SOPINSalt) {
		return ErrPINInvalid
	}
	if err := m.tpm.SetHierarchyAuth(hierarchyOwner, "", newUserPIN); err != nil {
		if isAuthError(err) {
			if retryErr := m.tpm.SetHierarchyAuth(hierarchyOwner, newUserPIN, newUserPIN); retryErr != nil {
				if isAuthError(retryErr) {
					return ErrHierarchyAuthMismatch
				}
				return retryErr
			}
		} else {
			return err
		}
	}
	hash, salt, err := legacyHashPIN(newUserPIN)
	if err != nil {
		return err
	}
	state.UserPINHash = hash
	state.UserPINSalt = salt
	return m.persistState(state)
}

func (m *TPMPINManager) ChangeSOPIN(currentSOPIN, newSOPIN string) error {
	if err := validatePINLength(newSOPIN); err != nil {
		return err
	}
	state := m.loadStateCopy()
	if !state.SOPINSet && len(state.SOPINHash) == 0 {
		return ErrPINNotSet
	}
	if state.SOPINHierarchyBound {
		if err := m.tpm.SetHierarchyAuth(hierarchyEndorsement, currentSOPIN, currentSOPIN); err != nil {
			if isAuthError(err) {
				return ErrInvalidCurrentPIN
			}
			return err
		}
	} else if len(state.SOPINHash) > 0 {
		if !legacyVerifyPIN(currentSOPIN, state.SOPINHash, state.SOPINSalt) {
			return ErrInvalidCurrentPIN
		}
	}
	// Determine the current hierarchy auth for the TPM call.
	// For legacy hash upgrades, the hierarchy was never password-protected.
	oldHierarchyAuth := currentSOPIN
	if !state.SOPINHierarchyBound && len(state.SOPINHash) > 0 {
		oldHierarchyAuth = ""
	}
	if err := m.tpm.SetHierarchyAuth(hierarchyEndorsement, oldHierarchyAuth, newSOPIN); err != nil {
		return err
	}
	state.SOPINSet = true
	state.SOPINHierarchyBound = true
	state.SOPINHash = nil
	state.SOPINSalt = nil
	return m.persistState(state)
}

func (m *TPMPINManager) ChangeUserPIN(currentUserPIN, newUserPIN string) error {
	if err := validatePINLength(newUserPIN); err != nil {
		return err
	}
	state := m.loadStateCopy()
	if len(state.UserPINHash) == 0 {
		return ErrPINNotSet
	}
	if !legacyVerifyPIN(currentUserPIN, state.UserPINHash, state.UserPINSalt) {
		return ErrInvalidCurrentPIN
	}
	if err := m.tpm.SetHierarchyAuth(hierarchyOwner, currentUserPIN, newUserPIN); err != nil {
		return err
	}
	hash, salt, err := legacyHashPIN(newUserPIN)
	if err != nil {
		return err
	}
	state.UserPINHash = hash
	state.UserPINSalt = salt
	return m.persistState(state)
}

func (m *TPMPINManager) VerifySOPIN(pin string) error {
	state := m.loadStateCopy()
	if err := m.checkLockout(state); err != nil {
		return err
	}
	if state.SOPINHierarchyBound {
		if err := m.tpm.SetHierarchyAuth(hierarchyEndorsement, pin, pin); err != nil {
			if isAuthError(err) {
				return m.recordFailedAttempt(state)
			}
			return err
		}
		return m.resetFailedAttempts(state)
	}
	if len(state.SOPINHash) == 0 {
		return ErrPINNotSet
	}
	if !legacyVerifyPIN(pin, state.SOPINHash, state.SOPINSalt) {
		return m.recordFailedAttempt(state)
	}
	return m.resetFailedAttempts(state)
}

func (m *TPMPINManager) VerifyUserPIN(pin string) error {
	state := m.loadStateCopy()
	if err := m.checkLockout(state); err != nil {
		return err
	}
	if len(state.UserPINHash) == 0 {
		return ErrPINNotSet
	}
	if !legacyVerifyPIN(pin, state.UserPINHash, state.UserPINSalt) {
		return m.recordFailedAttempt(state)
	}
	return m.resetFailedAttempts(state)
}

func (m *TPMPINManager) GetLockoutStatus() *LockoutStatus {
	state := m.state.Load()
	tpmFailed, tpmMaxFail, _, tpmRecovery, err := m.tpm.GetLockoutInfo()
	if err != nil {
		return m.localLockoutStatus(state)
	}
	failedAttempts := state.FailedAttempts
	if tpmFailed > failedAttempts {
		failedAttempts = tpmFailed
	}
	maxAttempts := m.lockoutCfg.MaxAttempts
	if tpmMaxFail > 0 && tpmMaxFail < maxAttempts {
		maxAttempts = tpmMaxFail
	}
	return &LockoutStatus{
		FailedAttempts:  failedAttempts,
		MaxAttempts:     maxAttempts,
		IsLocked:        failedAttempts >= maxAttempts,
		LockoutUntil:    state.LockoutUntil,
		RecoverySeconds: tpmRecovery,
	}
}

func (m *TPMPINManager) ResetLockout(soPIN string) error {
	state := m.loadStateCopy()
	if !state.SOPINSet && len(state.SOPINHash) == 0 {
		return ErrPINNotSet
	}
	if state.SOPINHierarchyBound {
		if err := m.tpm.SetHierarchyAuth(hierarchyEndorsement, soPIN, soPIN); err != nil {
			if isAuthError(err) {
				return ErrPINInvalid
			}
			return err
		}
	} else if !legacyVerifyPIN(soPIN, state.SOPINHash, state.SOPINSalt) {
		return ErrPINInvalid
	}
	if err := m.tpm.DictionaryAttackLockoutReset([]byte(soPIN)); err != nil {
		return err
	}
	state.FailedAttempts = 0
	state.LockoutUntil = time.Time{}
	state.LastFailedAt = time.Time{}
	return m.persistState(state)
}

func (m *TPMPINManager) IsInitialized() bool {
	state := m.state.Load()
	return state.SOPINSet || len(state.SOPINHash) > 0 || m.tpm.IsProvisioned()
}

func (m *TPMPINManager) SOPINSet() bool {
	state := m.state.Load()
	return state.SOPINSet || len(state.SOPINHash) > 0 || m.tpm.IsProvisioned()
}

func (m *TPMPINManager) UserPINSet() bool {
	return len(m.state.Load().UserPINHash) > 0
}

func (m *TPMPINManager) SeedUserPIN(userPIN string) error {
	if err := validatePINLength(userPIN); err != nil {
		return err
	}
	state := m.loadStateCopy()
	if len(state.UserPINHash) > 0 {
		return nil
	}
	hash, salt, err := legacyHashPIN(userPIN)
	if err != nil {
		return err
	}
	state.UserPINHash = hash
	state.UserPINSalt = salt
	return m.persistState(state)
}

func (m *TPMPINManager) loadStateCopy() *PINState {
	current := m.state.Load()
	cp := *current
	cp.SOPINHash = copyBytes(current.SOPINHash)
	cp.SOPINSalt = copyBytes(current.SOPINSalt)
	cp.UserPINHash = copyBytes(current.UserPINHash)
	cp.UserPINSalt = copyBytes(current.UserPINSalt)
	return &cp
}

func (m *TPMPINManager) persistState(state *PINState) error {
	if err := legacySaveState(m.statePath, state); err != nil {
		return err
	}
	m.state.Store(state)
	return nil
}

func (m *TPMPINManager) checkLockout(state *PINState) error {
	if state.FailedAttempts < m.lockoutCfg.MaxAttempts {
		return nil
	}
	if state.LockoutUntil.IsZero() {
		return nil
	}
	if time.Now().UTC().Before(state.LockoutUntil) {
		return ErrPINLocked
	}
	state.FailedAttempts = 0
	state.LockoutUntil = time.Time{}
	state.LastFailedAt = time.Time{}
	_ = m.persistState(state)
	return nil
}

func (m *TPMPINManager) recordFailedAttempt(state *PINState) error {
	state.FailedAttempts++
	state.LastFailedAt = time.Now().UTC()
	if state.FailedAttempts >= m.lockoutCfg.MaxAttempts {
		state.LockoutUntil = time.Now().UTC().Add(m.lockoutCfg.LockoutDuration)
	}
	if err := m.persistState(state); err != nil {
		return err
	}
	return ErrPINInvalid
}

func (m *TPMPINManager) resetFailedAttempts(state *PINState) error {
	if state.FailedAttempts == 0 {
		return nil
	}
	state.FailedAttempts = 0
	state.LockoutUntil = time.Time{}
	state.LastFailedAt = time.Time{}
	return m.persistState(state)
}

func (m *TPMPINManager) localLockoutStatus(state *PINState) *LockoutStatus {
	now := time.Now().UTC()
	isLocked := state.FailedAttempts >= m.lockoutCfg.MaxAttempts &&
		!state.LockoutUntil.IsZero() && now.Before(state.LockoutUntil)
	var recoverySeconds int
	if isLocked {
		recoverySeconds = int(time.Until(state.LockoutUntil).Seconds())
		if recoverySeconds < 0 {
			recoverySeconds = 0
		}
	}
	return &LockoutStatus{
		FailedAttempts:  state.FailedAttempts,
		MaxAttempts:     m.lockoutCfg.MaxAttempts,
		IsLocked:        isLocked,
		LockoutUntil:    state.LockoutUntil,
		RecoverySeconds: recoverySeconds,
	}
}

// FilePINManager implements PINBackend using Argon2id hashing and file-based persistence.
//
// Deprecated: Use [NewService] with a [SoftwareBackend] instead.
type FilePINManager struct {
	statePath  string
	lockoutCfg LockoutConfig
	state      atomic.Pointer[PINState]
}

// NewFilePINManager creates a new software-based PIN manager.
//
// Deprecated: Use [NewService] with a [SoftwareBackend] instead.
func NewFilePINManager(statePath string, lockoutCfg LockoutConfig) (*FilePINManager, error) {
	state, err := legacyLoadState(statePath)
	if err != nil {
		return nil, err
	}
	mgr := &FilePINManager{statePath: statePath, lockoutCfg: lockoutCfg}
	mgr.state.Store(state)
	return mgr, nil
}

func (m *FilePINManager) SetMaxAttempts(n int) { m.lockoutCfg.MaxAttempts = n }
func (m *FilePINManager) Strategy() StrategyID { return StrategySoftware }

func (m *FilePINManager) SetSOPIN(currentSOPIN, newSOPIN string) error {
	if err := validatePINLength(newSOPIN); err != nil {
		return err
	}
	state := m.loadStateCopy()
	if len(state.SOPINHash) > 0 {
		if currentSOPIN == "" {
			return ErrPINAlreadySet
		}
		if !legacyVerifyPIN(currentSOPIN, state.SOPINHash, state.SOPINSalt) {
			return ErrInvalidCurrentPIN
		}
	} else if currentSOPIN != "" {
		return ErrPINNotSet
	}
	hash, salt, err := legacyHashPIN(newSOPIN)
	if err != nil {
		return err
	}
	state.SOPINSet = true
	state.SOPINHash = hash
	state.SOPINSalt = salt
	return m.persistState(state)
}

func (m *FilePINManager) SetUserPIN(soPIN, newUserPIN string) error {
	if err := validatePINLength(newUserPIN); err != nil {
		return err
	}
	state := m.loadStateCopy()
	if len(state.SOPINHash) == 0 {
		return ErrSOPINRequired
	}
	if !legacyVerifyPIN(soPIN, state.SOPINHash, state.SOPINSalt) {
		return ErrPINInvalid
	}
	hash, salt, err := legacyHashPIN(newUserPIN)
	if err != nil {
		return err
	}
	state.UserPINHash = hash
	state.UserPINSalt = salt
	return m.persistState(state)
}

func (m *FilePINManager) ChangeSOPIN(currentSOPIN, newSOPIN string) error {
	if err := validatePINLength(newSOPIN); err != nil {
		return err
	}
	state := m.loadStateCopy()
	if len(state.SOPINHash) == 0 {
		return ErrPINNotSet
	}
	if !legacyVerifyPIN(currentSOPIN, state.SOPINHash, state.SOPINSalt) {
		return ErrInvalidCurrentPIN
	}
	hash, salt, err := legacyHashPIN(newSOPIN)
	if err != nil {
		return err
	}
	state.SOPINSet = true
	state.SOPINHash = hash
	state.SOPINSalt = salt
	return m.persistState(state)
}

func (m *FilePINManager) ChangeUserPIN(currentUserPIN, newUserPIN string) error {
	if err := validatePINLength(newUserPIN); err != nil {
		return err
	}
	state := m.loadStateCopy()
	if len(state.UserPINHash) == 0 {
		return ErrPINNotSet
	}
	if !legacyVerifyPIN(currentUserPIN, state.UserPINHash, state.UserPINSalt) {
		return ErrInvalidCurrentPIN
	}
	hash, salt, err := legacyHashPIN(newUserPIN)
	if err != nil {
		return err
	}
	state.UserPINHash = hash
	state.UserPINSalt = salt
	return m.persistState(state)
}

func (m *FilePINManager) VerifySOPIN(pin string) error {
	state := m.loadStateCopy()
	if err := m.checkLockout(state); err != nil {
		return err
	}
	if len(state.SOPINHash) == 0 {
		return ErrPINNotSet
	}
	if !legacyVerifyPIN(pin, state.SOPINHash, state.SOPINSalt) {
		return m.recordFailedAttempt(state)
	}
	return m.resetFailedAttempts(state)
}

func (m *FilePINManager) VerifyUserPIN(pin string) error {
	state := m.loadStateCopy()
	if err := m.checkLockout(state); err != nil {
		return err
	}
	if len(state.UserPINHash) == 0 {
		return ErrPINNotSet
	}
	if !legacyVerifyPIN(pin, state.UserPINHash, state.UserPINSalt) {
		return m.recordFailedAttempt(state)
	}
	return m.resetFailedAttempts(state)
}

func (m *FilePINManager) GetLockoutStatus() *LockoutStatus {
	state := m.state.Load()
	now := time.Now().UTC()
	isLocked := state.FailedAttempts >= m.lockoutCfg.MaxAttempts &&
		!state.LockoutUntil.IsZero() && now.Before(state.LockoutUntil)
	var recoverySeconds int
	if isLocked {
		recoverySeconds = int(time.Until(state.LockoutUntil).Seconds())
		if recoverySeconds < 0 {
			recoverySeconds = 0
		}
	}
	return &LockoutStatus{
		FailedAttempts:  state.FailedAttempts,
		MaxAttempts:     m.lockoutCfg.MaxAttempts,
		IsLocked:        isLocked,
		LockoutUntil:    state.LockoutUntil,
		RecoverySeconds: recoverySeconds,
	}
}

func (m *FilePINManager) ResetLockout(soPIN string) error {
	state := m.loadStateCopy()
	if len(state.SOPINHash) == 0 {
		return ErrPINNotSet
	}
	if !legacyVerifyPIN(soPIN, state.SOPINHash, state.SOPINSalt) {
		return ErrPINInvalid
	}
	state.FailedAttempts = 0
	state.LockoutUntil = time.Time{}
	state.LastFailedAt = time.Time{}
	return m.persistState(state)
}

func (m *FilePINManager) IsInitialized() bool {
	state := m.state.Load()
	return state.SOPINSet || len(state.SOPINHash) > 0
}

func (m *FilePINManager) SOPINSet() bool {
	state := m.state.Load()
	return state.SOPINSet || len(state.SOPINHash) > 0
}

func (m *FilePINManager) UserPINSet() bool {
	return len(m.state.Load().UserPINHash) > 0
}

func (m *FilePINManager) SeedUserPIN(userPIN string) error {
	if err := validatePINLength(userPIN); err != nil {
		return err
	}
	state := m.loadStateCopy()
	if len(state.UserPINHash) > 0 {
		return nil
	}
	hash, salt, err := legacyHashPIN(userPIN)
	if err != nil {
		return err
	}
	state.UserPINHash = hash
	state.UserPINSalt = salt
	return m.persistState(state)
}

func (m *FilePINManager) loadStateCopy() *PINState {
	current := m.state.Load()
	cp := *current
	cp.SOPINHash = copyBytes(current.SOPINHash)
	cp.SOPINSalt = copyBytes(current.SOPINSalt)
	cp.UserPINHash = copyBytes(current.UserPINHash)
	cp.UserPINSalt = copyBytes(current.UserPINSalt)
	return &cp
}

func (m *FilePINManager) persistState(state *PINState) error {
	if err := legacySaveState(m.statePath, state); err != nil {
		return err
	}
	m.state.Store(state)
	return nil
}

func (m *FilePINManager) checkLockout(state *PINState) error {
	if state.FailedAttempts < m.lockoutCfg.MaxAttempts {
		return nil
	}
	if state.LockoutUntil.IsZero() {
		return nil
	}
	if time.Now().UTC().Before(state.LockoutUntil) {
		return ErrPINLocked
	}
	state.FailedAttempts = 0
	state.LockoutUntil = time.Time{}
	state.LastFailedAt = time.Time{}
	_ = m.persistState(state)
	return nil
}

func (m *FilePINManager) recordFailedAttempt(state *PINState) error {
	state.FailedAttempts++
	state.LastFailedAt = time.Now().UTC()
	if state.FailedAttempts >= m.lockoutCfg.MaxAttempts {
		state.LockoutUntil = time.Now().UTC().Add(m.computeLockoutDuration(state.FailedAttempts))
	}
	if err := m.persistState(state); err != nil {
		return err
	}
	return ErrPINInvalid
}

func (m *FilePINManager) resetFailedAttempts(state *PINState) error {
	if state.FailedAttempts == 0 {
		return nil
	}
	state.FailedAttempts = 0
	state.LockoutUntil = time.Time{}
	state.LastFailedAt = time.Time{}
	return m.persistState(state)
}

func (m *FilePINManager) computeLockoutDuration(failedAttempts int) time.Duration {
	base := m.lockoutCfg.LockoutDuration
	if !m.lockoutCfg.Backoff {
		return base
	}
	exponent := failedAttempts - m.lockoutCfg.MaxAttempts
	if exponent < 0 {
		exponent = 0
	}
	duration := base
	for i := 0; i < exponent; i++ {
		duration *= 2
		if duration > maxBackoffDuration {
			return maxBackoffDuration
		}
	}
	return duration
}
