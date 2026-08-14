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

package module

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// Storage prefixes for different data types
const (
	prefixToken   = "pkcs11/tokens/"
	prefixObject  = "pkcs11/objects/"
	prefixSlot    = "pkcs11/slots/"
	prefixCounter = "pkcs11/counters/"
)

// PersistentTokenState represents the serializable state of a token.
type PersistentTokenState struct {
	SlotID      uint64    `json:"slot_id"`
	Label       string    `json:"label"`
	SOPinHash   []byte    `json:"so_pin_hash"`
	UserPinHash []byte    `json:"user_pin_hash"`
	Initialized bool      `json:"initialized"`
	Flags       TokenFlag `json:"flags"`
	// FailedUserPIN and FailedSOPIN carry the consecutive-failure counters that
	// drive CKR_PIN_LOCKED. They are persisted because the lockout is a property
	// of the token, not of the library instance (v3.2 §3.2 describes
	// CKF_USER_PIN_LOCKED as token state): held only in memory, the whole budget
	// resets on C_Finalize, and an attacker recovers a four-digit PIN by
	// re-initializing the library every three guesses.
	FailedUserPIN   uint32 `json:"failed_user_pin"`
	FailedSOPIN     uint32 `json:"failed_so_pin"`
	ManufacturerID  string `json:"manufacturer_id"`
	Model           string `json:"model"`
	SerialNumber    string `json:"serial_number"`
	HardwareVersion struct {
		Major uint8 `json:"major"`
		Minor uint8 `json:"minor"`
	} `json:"hardware_version"`
	FirmwareVersion struct {
		Major uint8 `json:"major"`
		Minor uint8 `json:"minor"`
	} `json:"firmware_version"`
	MaxPinLen uint64 `json:"max_pin_len"`
	MinPinLen uint64 `json:"min_pin_len"`
}

// PersistentAttribute represents a serializable PKCS#11 attribute.
type PersistentAttribute struct {
	Type  uint32 `json:"type"`
	Value []byte `json:"value"`
}

// PersistentObject represents the serializable state of a PKCS#11 object.
type PersistentObject struct {
	Handle        uint64                `json:"handle"`
	SlotID        uint64                `json:"slot_id"`
	Class         uint32                `json:"class"`
	KeyType       uint32                `json:"key_type"`
	Attributes    []PersistentAttribute `json:"attributes"`
	KeyID         string                `json:"key_id"`
	BackendName   string                `json:"backend_name"`
	IsToken       bool                  `json:"is_token"`
	IsPrivate     bool                  `json:"is_private"`
	IsSensitive   bool                  `json:"is_sensitive"`
	IsExtractable bool                  `json:"is_extractable"`
	IsModifiable  bool                  `json:"is_modifiable"`
	IsCopyable    bool                  `json:"is_copyable"`
	IsDestroyable bool                  `json:"is_destroyable"`
	CreatedAt     int64                 `json:"created_at"`
}

// ModuleStorage provides persistent storage for PKCS#11 module state.
type ModuleStorage struct {
	backend storage.Backend
	mu      sync.RWMutex

	// timeout bounds every backend round-trip. A store that stops responding
	// must surface as an error rather than block a Cryptoki call — and through
	// it the host application — indefinitely.
	timeout time.Duration
}

// DefaultStorageTimeout bounds a single persistence operation.
const DefaultStorageTimeout = 10 * time.Second

// NewModuleStorage creates a new storage instance with the given backend.
func NewModuleStorage(backend storage.Backend) *ModuleStorage {
	return &ModuleStorage{
		backend: backend,
		timeout: DefaultStorageTimeout,
	}
}

// SetTimeout overrides the per-operation storage timeout.
func (s *ModuleStorage) SetTimeout(timeout time.Duration) {
	if timeout > 0 {
		s.timeout = timeout
	}
}

// opContext returns a context bounded by the configured storage timeout, along
// with its cancel function.
func (s *ModuleStorage) opContext() (context.Context, context.CancelFunc) {
	timeout := s.timeout
	if timeout <= 0 {
		timeout = DefaultStorageTimeout
	}
	return context.WithTimeout(context.Background(), timeout)
}

// SaveTokenState persists the token state for a slot.
// failedUserPIN and failedSOPIN are the consecutive-failure counters that drive
// CKR_PIN_LOCKED. They are passed in rather than read off the Token because the
// authoritative copy lives on the slot's SessionManager, but the state they
// describe belongs to the token and so has to be written down with it.
func (s *ModuleStorage) SaveTokenState(slotID SlotID, token *Token, failedUserPIN, failedSOPIN uint32) error {
	if s.backend == nil {
		return nil // No persistence configured
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	state := &PersistentTokenState{
		SlotID:        uint64(slotID),
		SOPinHash:     token.SOPinHash,
		UserPinHash:   token.UserPinHash,
		Initialized:   token.Initialized,
		Flags:         token.Info.Flags,
		MaxPinLen:     token.Info.MaxPinLen,
		MinPinLen:     token.Info.MinPinLen,
		FailedUserPIN: failedUserPIN,
		FailedSOPIN:   failedSOPIN,
	}

	// Copy fixed-size arrays to strings
	state.Label = string(token.Info.Label[:])
	state.ManufacturerID = string(token.Info.ManufacturerID[:])
	state.Model = string(token.Info.Model[:])
	state.SerialNumber = string(token.Info.SerialNumber[:])
	state.HardwareVersion.Major = token.Info.HardwareVersion.Major
	state.HardwareVersion.Minor = token.Info.HardwareVersion.Minor
	state.FirmwareVersion.Major = token.Info.FirmwareVersion.Major
	state.FirmwareVersion.Minor = token.Info.FirmwareVersion.Minor

	data, err := json.Marshal(state)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to marshal token state", Err: err}
	}

	key := prefixToken + strconv.FormatUint(uint64(slotID), 10)
	ctx, cancel := s.opContext()
	defer cancel()
	if err := s.backend.Put(ctx, key, data); err != nil {
		return &errs.Wrapped{Msg: "failed to save token state", Err: err}
	}

	return nil
}

// maxAttemptCASRetries bounds the compare-and-swap retry loop for a failed-
// attempt counter. It is far above any realistic number of clients contending on
// one token's counter, so it only backstops a pathological live-lock rather than
// capping normal concurrency.
const maxAttemptCASRetries = 16

// ErrCorruptAttemptCounter is returned when a persisted failed-attempt counter
// does not parse as a uint32. Like the object-handle counter, a counter that
// cannot be read is not one that may be guessed: a lockout that silently resets
// to zero is a security fault, so the read fails loudly instead.
var ErrCorruptAttemptCounter = errors.New("pkcs11: corrupt failed-attempt counter")

// failedAttemptKey builds the dedicated storage key for a token's failed-attempt
// counter. The counters live under their own keys, apart from the token record,
// so a single failed attempt is an atomic increment of a small value rather than
// a read-modify-write of the whole token — which is what lets several remote-mode
// clients sharing one token accumulate failures without losing updates. It
// reports false for a user type that has no lockout counter.
func failedAttemptKey(slotID SlotID, userType UserType) (string, bool) {
	base := prefixCounter + "token/" + strconv.FormatUint(uint64(slotID), 10) + "/failed_"
	switch userType {
	case CKU_USER:
		return base + "user", true
	case CKU_SO:
		return base + "so", true
	default:
		return "", false
	}
}

// parseAttemptCounter decodes a stored counter value. An absent counter (nil) is
// zero; a malformed one is ErrCorruptAttemptCounter rather than a silent reset.
func parseAttemptCounter(data []byte) (uint32, error) {
	if len(data) == 0 {
		return 0, nil
	}
	v, err := strconv.ParseUint(string(data), 10, 32)
	if err != nil {
		return 0, &errs.Wrapped{Msg: "failed-attempt counter", Err: ErrCorruptAttemptCounter}
	}
	return uint32(v), nil
}

// IncrementFailedAttempt atomically adds one to the durable failed-attempt
// counter for (slotID, userType) and returns the new stored value.
//
// On a compare-and-swap-capable backend (the remote/clustered case) it uses a
// CAS retry loop so concurrent increments from several clients sharing one token
// accumulate rather than clobber each other; on a single-writer local backend it
// is a mutex-guarded read-modify-write. The returned value is authoritative — the
// caller writes it back into its optimistic in-memory counter. persisted is false
// when no durable backend is configured, telling the caller to advance its own
// in-memory counter instead.
func (s *ModuleStorage) IncrementFailedAttempt(slotID SlotID, userType UserType) (value uint32, persisted bool, err error) {
	if s.backend == nil {
		return 0, false, nil
	}
	key, ok := failedAttemptKey(slotID, userType)
	if !ok {
		return 0, false, nil
	}

	if cas, ok := s.backend.(storage.CompareAndSwapper); ok {
		v, err := s.incrementViaCAS(cas, key)
		return v, err == nil, err
	}

	// Single-writer local backend: the storage mutex makes read-modify-write
	// linearizable for this process, exactly as it does for PutIfAbsent.
	s.mu.Lock()
	defer s.mu.Unlock()
	v, err := s.incrementLocked(key)
	return v, err == nil, err
}

// incrementViaCAS performs the compare-and-swap retry loop for a counter key.
func (s *ModuleStorage) incrementViaCAS(cas storage.CompareAndSwapper, key string) (uint32, error) {
	for attempt := 0; attempt < maxAttemptCASRetries; attempt++ {
		ctx, cancel := s.opContext()
		current, getErr := s.backend.Get(ctx, key)
		var expected []byte
		switch {
		case getErr == nil:
			expected = current
		case errors.Is(getErr, storage.ErrNotFound):
			expected = nil // require-absent
		default:
			cancel()
			return 0, &errs.Wrapped{Msg: "failed to read lockout counter", Err: getErr}
		}

		curVal, parseErr := parseAttemptCounter(expected)
		if parseErr != nil {
			cancel()
			return 0, parseErr
		}
		next := curVal + 1
		nextBytes := []byte(strconv.FormatUint(uint64(next), 10))

		swapped, _, casErr := cas.CompareAndSwap(ctx, key, expected, nextBytes)
		cancel()
		if casErr != nil {
			return 0, &errs.Wrapped{Msg: "failed to update lockout counter", Err: casErr}
		}
		if swapped {
			return next, nil
		}
		// A concurrent writer moved the counter; re-read and retry.
	}
	return 0, &errs.Wrapped{Msg: "lockout counter contention", Err: ErrCorruptAttemptCounter}
}

// incrementLocked performs read-modify-write for a counter key under s.mu.
func (s *ModuleStorage) incrementLocked(key string) (uint32, error) {
	ctx, cancel := s.opContext()
	defer cancel()

	data, err := s.backend.Get(ctx, key)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return 0, &errs.Wrapped{Msg: "failed to read lockout counter", Err: err}
	}
	curVal, parseErr := parseAttemptCounter(data)
	if parseErr != nil {
		return 0, parseErr
	}
	next := curVal + 1
	if err := s.backend.Put(ctx, key, []byte(strconv.FormatUint(uint64(next), 10))); err != nil {
		return 0, &errs.Wrapped{Msg: "failed to update lockout counter", Err: err}
	}
	return next, nil
}

// ResetFailedAttempt clears the durable failed-attempt counter for
// (slotID, userType). A reset follows a successful authentication or an
// authorized PIN change, which invalidates every prior failure, so it is not
// accumulation-sensitive and is written as a plain set to zero.
func (s *ModuleStorage) ResetFailedAttempt(slotID SlotID, userType UserType) error {
	if s.backend == nil {
		return nil
	}
	key, ok := failedAttemptKey(slotID, userType)
	if !ok {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, cancel := s.opContext()
	defer cancel()
	if err := s.backend.Put(ctx, key, []byte("0")); err != nil {
		return &errs.Wrapped{Msg: "failed to reset lockout counter", Err: err}
	}
	return nil
}

// LoadFailedAttempts returns the durable failed-attempt counters for a token,
// preferring the dedicated counter keys and falling back to the token record's
// embedded snapshot for tokens persisted before the counters were split out.
// When it falls back, it seeds the dedicated key (write-if-absent) so subsequent
// atomic increments build on the migrated value rather than restarting from zero.
func (s *ModuleStorage) LoadFailedAttempts(slotID SlotID, recordUser, recordSO uint32) (user, so uint32, err error) {
	if s.backend == nil {
		return recordUser, recordSO, nil
	}
	user, err = s.loadOrSeedAttempt(slotID, CKU_USER, recordUser)
	if err != nil {
		return 0, 0, err
	}
	so, err = s.loadOrSeedAttempt(slotID, CKU_SO, recordSO)
	if err != nil {
		return 0, 0, err
	}
	return user, so, nil
}

// loadOrSeedAttempt reads one dedicated counter, seeding it from the record
// snapshot when absent so a pre-split token keeps the budget it had already spent.
func (s *ModuleStorage) loadOrSeedAttempt(slotID SlotID, userType UserType, recordValue uint32) (uint32, error) {
	key, ok := failedAttemptKey(slotID, userType)
	if !ok {
		return recordValue, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	ctx, cancel := s.opContext()
	defer cancel()

	data, err := s.backend.Get(ctx, key)
	if err == nil {
		return parseAttemptCounter(data)
	}
	if !errors.Is(err, storage.ErrNotFound) {
		return 0, &errs.Wrapped{Msg: "failed to read lockout counter", Err: err}
	}

	// Absent: migrate from the record snapshot. PutIfAbsent makes the seed
	// idempotent if two clients start together; the loser re-reads the winner's
	// value below.
	seed := []byte(strconv.FormatUint(uint64(recordValue), 10))
	stored, err := s.backend.PutIfAbsent(ctx, key, seed)
	if err != nil {
		return 0, &errs.Wrapped{Msg: "failed to seed lockout counter", Err: err}
	}
	if stored {
		return recordValue, nil
	}
	existing, err := s.backend.Get(ctx, key)
	if err != nil {
		return 0, &errs.Wrapped{Msg: "failed to read seeded lockout counter", Err: err}
	}
	return parseAttemptCounter(existing)
}

// LoadTokenState loads the token state for a slot.
func (s *ModuleStorage) LoadTokenState(slotID SlotID) (*PersistentTokenState, error) {
	if s.backend == nil {
		return nil, nil // No persistence configured
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	key := prefixToken + strconv.FormatUint(uint64(slotID), 10)
	ctx, cancel := s.opContext()
	defer cancel()
	data, err := s.backend.Get(ctx, key)
	if err != nil {
		if err == storage.ErrNotFound {
			return nil, nil // Token not initialized yet
		}
		return nil, &errs.Wrapped{Msg: "failed to load token state", Err: err}
	}

	var state PersistentTokenState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to unmarshal token state", Err: err}
	}

	return &state, nil
}

// getWithTimeout performs one bounded backend read, releasing its context
// before returning.
//
// It exists because defer is function-scoped: reading N objects in a loop with a
// deferred cancel each pushed N live timers and N defer records that ran only
// when LoadObjects returned, all while the storage read lock was held. A token
// with fifty thousand persisted objects held fifty thousand armed timers for the
// whole of C_Initialize, and the per-operation timeout the surrounding code took
// care to add was silently defeated.
func (s *ModuleStorage) getWithTimeout(key string) ([]byte, error) {
	ctx, cancel := s.opContext()
	defer cancel()
	return s.backend.Get(ctx, key)
}

// SaveObject persists a PKCS#11 object.
func (s *ModuleStorage) SaveObject(slotID SlotID, obj *Object) error {
	if s.backend == nil {
		return nil // No persistence configured
	}

	// Only persist token objects (not session objects)
	if !obj.IsToken {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	po := &PersistentObject{
		Handle:        uint64(obj.Handle),
		SlotID:        uint64(slotID),
		Class:         uint32(obj.Class),
		KeyType:       uint32(obj.KeyType),
		KeyID:         obj.KeyID,
		BackendName:   obj.BackendName,
		IsToken:       obj.IsToken,
		IsPrivate:     obj.IsPrivate,
		IsSensitive:   obj.IsSensitive,
		IsExtractable: obj.IsExtractable,
		IsModifiable:  obj.IsModifiable,
		IsCopyable:    obj.IsCopyable,
		IsDestroyable: obj.IsDestroyable,
	}

	// Convert attributes map to slice.
	//
	// A protected key's secret attributes are never written out. This store
	// holds object metadata, not key material: the material itself lives in the
	// backend, addressed by KeyID. Serializing CKA_VALUE or an RSA private
	// component here would place in the clear exactly the bytes that
	// CKA_SENSITIVE and CKA_EXTRACTABLE=CK_FALSE promise never leave the token.
	// Non-key classes (certificates, data objects) have no extractability
	// semantics: their CKA_VALUE is public object content and must persist.
	//
	// One key class has no backend copy to fall back on: a post-quantum private
	// key is generated in process and its seed exists only as CKA_VALUE (see
	// module_keygen_quantum.go). Withholding that leaves an object no operation
	// can use. The store is not the place to resolve that — writing the seed
	// out would break the promise above for the one class least able to afford
	// it — so quantumPrivateKeyPersistenceError refuses at generation time to
	// create a CKA_TOKEN post-quantum private key whose material this loop
	// would drop. A post-quantum private key that reaches here is one the
	// application declared CKA_SENSITIVE=CK_FALSE and CKA_EXTRACTABLE=CK_TRUE,
	// for which protected is false and CKA_VALUE persists like any other
	// attribute.
	protected := obj.protectsSensitiveAttributes()
	po.Attributes = make([]PersistentAttribute, 0, len(obj.Attributes))
	for attrType, value := range obj.Attributes {
		if protected && IsSensitiveAttribute(attrType) {
			continue
		}
		po.Attributes = append(po.Attributes, PersistentAttribute{
			Type:  uint32(attrType),
			Value: value,
		})
	}

	data, err := json.Marshal(po)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to marshal object", Err: err}
	}

	key := prefixObject + strconv.FormatUint(uint64(obj.Handle), 10)
	ctx, cancel := s.opContext()
	defer cancel()
	if err := s.backend.Put(ctx, key, data); err != nil {
		return &errs.Wrapped{Msg: "failed to save object", Err: err}
	}

	return nil
}

// LoadObjects loads all persisted objects for a slot.
func (s *ModuleStorage) LoadObjects(slotID SlotID) ([]*PersistentObject, error) {
	if s.backend == nil {
		return nil, nil // No persistence configured
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	ctx, cancel := s.opContext()
	defer cancel()
	keys, err := s.backend.List(ctx, prefixObject)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to list objects", Err: err}
	}

	var objects []*PersistentObject
	for _, key := range keys {
		data, err := s.getWithTimeout(key)
		if err != nil {
			// List reported this key exists, so a Get that now fails is an IO or
			// consistency fault, not an absence. Surfacing it lets C_Initialize
			// refuse rather than silently present a token missing one of its
			// objects.
			return nil, &errs.Wrapped{Msg: "failed to read persisted object " + key, Err: err}
		}

		var po PersistentObject
		if err := json.Unmarshal(data, &po); err != nil {
			// A record that will not unmarshal is corrupt. Dropping it silently
			// is the same data-loss-under-CKR_OK the caller must not do.
			return nil, &errs.Wrapped{Msg: "failed to unmarshal persisted object " + key, Err: err}
		}

		// Only return objects for the requested slot
		if po.SlotID == uint64(slotID) {
			objects = append(objects, &po)
		}
	}

	return objects, nil
}

// DeleteObject removes a persisted object.
func (s *ModuleStorage) DeleteObject(handle ObjectHandle) error {
	if s.backend == nil {
		return nil // No persistence configured
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	key := prefixObject + strconv.FormatUint(uint64(handle), 10)
	ctx, cancel := s.opContext()
	defer cancel()
	if err := s.backend.Delete(ctx, key); err != nil && err != storage.ErrNotFound {
		return &errs.Wrapped{Msg: "failed to delete object", Err: err}
	}

	return nil
}

// GetNextHandle returns the next available object handle.
func (s *ModuleStorage) GetNextHandle() (ObjectHandle, error) {
	if s.backend == nil {
		return 0, nil // Will use in-memory counter
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	key := prefixCounter + "object_handle"
	ctx, cancel := s.opContext()
	defer cancel()
	data, err := s.backend.Get(ctx, key)
	if err != nil && err != storage.ErrNotFound {
		return 0, &errs.Wrapped{Msg: "failed to get handle counter", Err: err}
	}

	var counter uint64 = 1
	if len(data) > 0 {
		// A counter that cannot be read is not a counter that may be guessed.
		// ParseUint returns 0 on a malformed value, and continuing from 1 would
		// reissue handles that already name live objects -- and because
		// ObjectManager.AddObject tries Update before Insert, the reissued
		// handle would silently REPLACE the object at that handle. An
		// application holding a handle to its RSA private key would find
		// different key material under it, and C_Sign would sign with the wrong
		// key. Failing the call is the only safe answer.
		stored, parseErr := strconv.ParseUint(string(data), 10, 64)
		if parseErr != nil {
			return 0, &errs.Wrapped{Msg: "corrupt object handle counter", Err: parseErr}
		}
		counter = stored
		counter++
	}

	putCtx, putCancel := s.opContext()
	defer putCancel()
	if err := s.backend.Put(putCtx, key, []byte(strconv.FormatUint(counter, 10))); err != nil {
		return 0, &errs.Wrapped{Msg: "failed to save handle counter", Err: err}
	}

	return ObjectHandle(counter), nil
}

// SetNextHandle sets the next available object handle.
func (s *ModuleStorage) SetNextHandle(handle ObjectHandle) error {
	if s.backend == nil {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	key := prefixCounter + "object_handle"
	ctx, cancel := s.opContext()
	defer cancel()
	if err := s.backend.Put(ctx, key, []byte(strconv.FormatUint(uint64(handle), 10))); err != nil {
		return &errs.Wrapped{Msg: "failed to save handle counter", Err: err}
	}

	return nil
}

// Close releases storage resources.
func (s *ModuleStorage) Close() error {
	if s.backend == nil {
		return nil
	}
	return s.backend.Close()
}

// RestoreObject converts a PersistentObject back to a module Object.
//
// Every persisted attribute is re-applied through Object.SetAttribute rather
// than written into the attribute map directly, so that a value read out of a
// token file passes through exactly the CK_ULONG width normalization a value
// supplied in a C_CreateObject template does. A token file written before that
// normalization existed holds four-byte CKA_CLASS and CKA_KEY_TYPE values;
// handing those back verbatim gives an application that allocated
// sizeof(CK_ULONG) four bytes of value and four bytes of its own uninitialized
// buffer, which is how pkcs11-provider came to decode a class as
// 0xFFFFFFFF00000002 and abandon the object. Restoring through the same single
// point means an upgraded deployment's existing keys are usable, not only the
// keys created after the upgrade.
func RestoreObject(po *PersistentObject) *Object {
	obj := &Object{
		Attributes: make(map[AttributeType][]byte, len(po.Attributes)),
	}

	for _, attr := range po.Attributes {
		obj.SetAttribute(AttributeType(attr.Type), attr.Value)
	}

	// The persisted scalars are applied after the attribute loop because they
	// are the record of what the object was, whereas SetAttribute derives the
	// same fields from whichever attributes happen to have been persisted. The
	// two agree for anything this module wrote — SaveObject copies them off one
	// object — and where an attribute was withheld from the file, as a
	// protected key's are, only the scalar carries the value at all.
	obj.Handle = ObjectHandle(po.Handle)
	obj.SlotID = SlotID(po.SlotID)
	obj.Class = ObjectClass(po.Class)
	obj.KeyType = KeyType(po.KeyType)
	obj.KeyID = po.KeyID
	obj.BackendName = po.BackendName
	obj.IsToken = po.IsToken
	obj.IsPrivate = po.IsPrivate
	obj.IsSensitive = po.IsSensitive
	obj.IsExtractable = po.IsExtractable
	obj.IsModifiable = po.IsModifiable
	obj.IsCopyable = po.IsCopyable
	obj.IsDestroyable = po.IsDestroyable

	return obj
}

// RestoreTokenState applies persisted state to a Token.
func RestoreTokenState(token *Token, state *PersistentTokenState) {
	token.SOPinHash = state.SOPinHash
	token.UserPinHash = state.UserPinHash
	token.Initialized = state.Initialized
	token.Info.Flags = state.Flags
	token.Info.MaxPinLen = state.MaxPinLen
	token.Info.MinPinLen = state.MinPinLen
	token.Info.HardwareVersion.Major = state.HardwareVersion.Major
	token.Info.HardwareVersion.Minor = state.HardwareVersion.Minor
	token.Info.FirmwareVersion.Major = state.FirmwareVersion.Major
	token.Info.FirmwareVersion.Minor = state.FirmwareVersion.Minor

	// The setters blank-pad rather than copy, because CK_TOKEN_INFO's character
	// fields are space-filled and not NUL-terminated (v3.2 §3.2). A bare copy
	// left whatever the array already held beyond the restored string, and left
	// a shorter restored value trailed by NULs where an application expects
	// spaces.
	token.Info.SetLabel(trimPaddedString([]byte(state.Label)))
	token.Info.SetManufacturerID(trimPaddedString([]byte(state.ManufacturerID)))
	token.Info.SetModel(trimPaddedString([]byte(state.Model)))
	token.Info.SetSerialNumber(trimPaddedString([]byte(state.SerialNumber)))
}
