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
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"sync/atomic"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/mem"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// Storage keys for persisted PIN records.
const (
	soPINStorageKey   = "so-pin"
	userPINStorageKey = "user-pin"
)

// Compile-time interface checks.
var _ PINBackend = (*SoftwareBackend)(nil)
var _ FIDO2HashVerifier = (*SoftwareBackend)(nil)

// SoftwareBackend implements PINBackend using Argon2id/PBKDF2 password hashing
// for PIN protection. PINs are hashed with a random salt and stored as
// PINRecord JSON blobs in the storage backend.
//
// The HashConfig determines which algorithm (Argon2id or PBKDF2) and parameters
// are used for hashing. AutoDetectHashConfig selects PBKDF2 in FIPS mode and
// Argon2id otherwise.
//
// PIN records for both SO and user PINs are persisted to storage (when provided)
// so that they survive process restarts.
//
// The FIDO2 hash is held in a GuardedBuffer (mlock'd, guard-paged memory)
// and is lazily recomputed on the first successful VerifyUserPIN after
// restart.
//
// All mutable state is managed through atomic operations for lock-free
// concurrent access.
type SoftwareBackend struct {
	store      storage.Backend
	hashConfig HashConfig
	soRecord   atomic.Pointer[PINRecord]
	userRecord atomic.Pointer[PINRecord]
	fido2Guard atomic.Pointer[mem.GuardedBuffer]
	soPINSet   atomic.Bool
	userPINSet atomic.Bool
}

// NewSoftwareBackend creates a new SoftwareBackend that uses the given
// HashConfig for PIN hashing. If store is non-nil, PIN records are loaded
// from storage on construction and persisted on every update. Pass nil
// for in-memory-only operation (tests).
func NewSoftwareBackend(store storage.Backend, hashConfig HashConfig) (*SoftwareBackend, error) {
	b := &SoftwareBackend{
		store:      store,
		hashConfig: hashConfig,
	}
	if store != nil {
		if err := b.loadPersistedRecords(); err != nil {
			return nil, err
		}
	}
	return b, nil
}

// Strategy returns StrategySoftware.
func (b *SoftwareBackend) Strategy() StrategyID {
	return StrategySoftware
}

// SetSOPIN sets the Security Officer PIN. If the SO PIN is already set and
// currentSOPIN is empty, ErrPINAlreadySet is returned. If the SO PIN is
// already set, the current SO PIN is verified before the new one is stored.
func (b *SoftwareBackend) SetSOPIN(currentSOPIN, newSOPIN string) error {
	if err := validatePINLength(newSOPIN); err != nil {
		return err
	}

	if b.soPINSet.Load() {
		if currentSOPIN == "" {
			return ErrPINAlreadySet
		}
		if err := b.verifyRecord(currentSOPIN, b.soRecord.Load()); err != nil {
			return ErrInvalidCurrentPIN
		}
	}

	return b.hashAndStoreSOPIN(newSOPIN)
}

// SetUserPIN sets the user PIN using SO PIN authorization. The SO PIN must
// be set and the provided soPIN must match. If the user PIN is already set,
// ErrPINAlreadySet is returned.
func (b *SoftwareBackend) SetUserPIN(soPIN, newUserPIN string) error {
	if err := validatePINLength(newUserPIN); err != nil {
		return err
	}

	if !b.soPINSet.Load() {
		return ErrSOPINRequired
	}

	if err := b.verifyRecord(soPIN, b.soRecord.Load()); err != nil {
		return ErrPINInvalid
	}

	if b.userPINSet.Load() {
		return ErrPINAlreadySet
	}

	if err := b.hashAndStoreUserPIN(newUserPIN); err != nil {
		return err
	}

	b.cacheFIDO2Hash([]byte(newUserPIN))
	return nil
}

// ChangeSOPIN changes the SO PIN from currentSOPIN to newSOPIN. The current
// SO PIN is verified before the change is applied.
func (b *SoftwareBackend) ChangeSOPIN(currentSOPIN, newSOPIN string) error {
	if err := validatePINLength(newSOPIN); err != nil {
		return err
	}

	if !b.soPINSet.Load() {
		return ErrPINNotSet
	}

	if err := b.verifyRecord(currentSOPIN, b.soRecord.Load()); err != nil {
		return ErrInvalidCurrentPIN
	}

	return b.hashAndStoreSOPIN(newSOPIN)
}

// ChangeUserPIN changes the user PIN from currentUserPIN to newUserPIN.
// The current user PIN is verified before the change is applied. The FIDO2
// hash cache is updated with the new PIN.
func (b *SoftwareBackend) ChangeUserPIN(currentUserPIN, newUserPIN string) error {
	if err := validatePINLength(newUserPIN); err != nil {
		return err
	}

	if !b.userPINSet.Load() {
		return ErrPINNotSet
	}

	if err := b.verifyRecord(currentUserPIN, b.userRecord.Load()); err != nil {
		return ErrInvalidCurrentPIN
	}

	if err := b.hashAndStoreUserPIN(newUserPIN); err != nil {
		return err
	}

	b.cacheFIDO2Hash([]byte(newUserPIN))
	return nil
}

// VerifySOPIN verifies the SO PIN by re-deriving the hash from the stored
// record and performing a constant-time comparison.
func (b *SoftwareBackend) VerifySOPIN(pin string) error {
	if !b.soPINSet.Load() {
		return ErrPINNotSet
	}
	return b.verifyRecord(pin, b.soRecord.Load())
}

// VerifyUserPIN verifies the user PIN by re-deriving the hash from the
// stored record. On success, lazily recomputes the FIDO2 hash if it is
// not yet cached (e.g., after restart).
func (b *SoftwareBackend) VerifyUserPIN(pin string) error {
	if !b.userPINSet.Load() {
		return ErrPINNotSet
	}

	if err := b.verifyRecord(pin, b.userRecord.Load()); err != nil {
		return err
	}

	// Lazy FIDO2 hash recomputation after restart.
	guard := b.fido2Guard.Load()
	if guard == nil || guard.IsFreed() {
		b.cacheFIDO2Hash([]byte(pin))
	}

	return nil
}

// IsInitialized returns true if the SO PIN has been set.
func (b *SoftwareBackend) IsInitialized() bool {
	return b.soPINSet.Load()
}

// SOPINSet returns true if the SO PIN has been configured.
func (b *SoftwareBackend) SOPINSet() bool {
	return b.soPINSet.Load()
}

// UserPINSet returns true if the user PIN has been configured.
func (b *SoftwareBackend) UserPINSet() bool {
	return b.userPINSet.Load()
}

// GetLockoutStatus returns nil. The SoftwareBackend relies on the hash
// as the protection mechanism and does not implement lockout counters.
func (b *SoftwareBackend) GetLockoutStatus() *LockoutStatus {
	return nil
}

// ResetLockout returns nil. The SoftwareBackend has no lockout mechanism
// to reset.
func (b *SoftwareBackend) ResetLockout(_ string) error {
	return nil
}

// VerifyFIDO2Hash verifies a FIDO2 PIN hash (SHA-256(PIN)[:16]) against
// the cached guarded buffer using constant-time comparison.
func (b *SoftwareBackend) VerifyFIDO2Hash(hash []byte) bool {
	if len(hash) != FIDO2PINHashSize {
		return false
	}

	guard := b.fido2Guard.Load()
	if guard == nil || guard.IsFreed() {
		return false
	}

	return subtle.ConstantTimeCompare(guard.Bytes(), hash) == 1
}

// Close frees the GuardedBuffer holding the FIDO2 hash. Safe to call
// multiple times.
func (b *SoftwareBackend) Close() {
	if guard := b.fido2Guard.Load(); guard != nil {
		guard.Free()
	}
}

// loadPersistedRecords loads SO and user PIN records from storage.
// ErrNotFound is silently ignored (fresh install). Other errors are
// wrapped as ErrStorageLoadFailed.
func (b *SoftwareBackend) loadPersistedRecords() error {
	if err := b.loadRecord(soPINStorageKey, &b.soRecord, &b.soPINSet); err != nil {
		return err
	}
	return b.loadRecord(userPINStorageKey, &b.userRecord, &b.userPINSet)
}

// loadRecord loads a single PIN record from storage into the given atomic
// pointer and sets the flag if successful.
func (b *SoftwareBackend) loadRecord(key string, ptr *atomic.Pointer[PINRecord], flag *atomic.Bool) error {
	data, err := b.store.Get(context.Background(), key)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil
		}
		return &ErrStorageLoadFailed{Key: key, Cause: err}
	}

	var record PINRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return &ErrStorageLoadFailed{Key: key, Cause: err}
	}

	ptr.Store(&record)
	flag.Store(true)
	return nil
}

// verifyRecord verifies a PIN against a PINRecord using the hash.go
// infrastructure. Returns ErrPINInvalid if the PIN does not match or
// the record is nil.
func (b *SoftwareBackend) verifyRecord(pin string, record *PINRecord) error {
	if record == nil {
		return ErrPINNotSet
	}

	ok, err := verifyPINRecord(pin, record)
	if err != nil {
		return ErrPINInvalid
	}
	if !ok {
		return ErrPINInvalid
	}

	return nil
}

// hashAndStoreSOPIN hashes the SO PIN, stores the record atomically,
// and persists to storage if configured.
func (b *SoftwareBackend) hashAndStoreSOPIN(pin string) error {
	record, err := hashPINWithConfig(pin, b.hashConfig)
	if err != nil {
		return err
	}

	if b.store != nil {
		if err := b.persistRecord(soPINStorageKey, record); err != nil {
			return err
		}
	}

	b.soRecord.Store(record)
	b.soPINSet.Store(true)
	return nil
}

// hashAndStoreUserPIN hashes the user PIN, persists it to storage (if
// configured), and updates the in-memory atomic state.
func (b *SoftwareBackend) hashAndStoreUserPIN(pin string) error {
	record, err := hashPINWithConfig(pin, b.hashConfig)
	if err != nil {
		return err
	}

	if b.store != nil {
		if err := b.persistRecord(userPINStorageKey, record); err != nil {
			return err
		}
	}

	b.userRecord.Store(record)
	b.userPINSet.Store(true)
	return nil
}

// persistRecord marshals a PINRecord to JSON and writes it to storage.
func (b *SoftwareBackend) persistRecord(key string, record *PINRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return &ErrStoragePersistFailed{Key: key, Cause: err}
	}
	if err := b.store.Put(context.Background(), key, data); err != nil {
		return &ErrStoragePersistFailed{Key: key, Cause: err}
	}
	return nil
}

// cacheFIDO2Hash computes the FIDO2 PIN hash and stores it in a
// GuardedBuffer. The previous buffer (if any) is freed.
func (b *SoftwareBackend) cacheFIDO2Hash(pinBytes []byte) {
	hash := computeFIDO2PINHashFromBytes(pinBytes)
	defer mem.Zero(hash)

	guard, err := mem.NewGuardedBuffer(FIDO2PINHashSize)
	if err != nil {
		return
	}
	guard.Write(hash)

	// Free the old buffer.
	if old := b.fido2Guard.Swap(guard); old != nil {
		old.Free()
	}
}
