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
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/require"
)

func TestNewModuleStorage(t *testing.T) {
	backend := storage.NewMemory()
	s := NewModuleStorage(backend)

	require.NotNil(t, s)
	require.NotNil(t, s.backend)
}

func TestModuleStorage_NilBackend(t *testing.T) {
	s := NewModuleStorage(nil)

	// All operations should succeed silently with nil backend
	err := s.SaveTokenState(1, &Token{}, 0, 0)
	require.NoError(t, err)

	state, err := s.LoadTokenState(1)
	require.NoError(t, err)
	require.Nil(t, state)

	err = s.SaveObject(1, &Object{IsToken: true})
	require.NoError(t, err)

	objects, err := s.LoadObjects(1)
	require.NoError(t, err)
	require.Nil(t, objects)

	err = s.DeleteObject(1)
	require.NoError(t, err)

	handle, err := s.GetNextHandle()
	require.NoError(t, err)
	require.Equal(t, ObjectHandle(0), handle)

	err = s.SetNextHandle(10)
	require.NoError(t, err)

	err = s.Close()
	require.NoError(t, err)
}

func TestModuleStorage_TokenState(t *testing.T) {
	backend := storage.NewMemory()
	s := NewModuleStorage(backend)

	// Create a token with some state
	token := &Token{
		SOPinHash:   []byte("hashed-so-pin"),
		UserPinHash: []byte("hashed-user-pin"),
		Initialized: true,
		Info: TokenInfo{
			Flags:     CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED,
			MaxPinLen: 64,
			MinPinLen: 4,
		},
	}
	token.Info.SetLabel("TestToken")
	token.Info.SetManufacturerID("TestManufacturer")
	token.Info.SetModel("TestModel")
	token.Info.SetSerialNumber("12345678")
	token.Info.HardwareVersion = Version{Major: 1, Minor: 0}
	token.Info.FirmwareVersion = Version{Major: 2, Minor: 1}

	// Save token state
	err := s.SaveTokenState(SlotID(0), token, 0, 0)
	require.NoError(t, err)

	// Load token state
	state, err := s.LoadTokenState(SlotID(0))
	require.NoError(t, err)
	require.NotNil(t, state)

	require.Equal(t, uint64(0), state.SlotID)
	require.Equal(t, token.SOPinHash, state.SOPinHash)
	require.Equal(t, token.UserPinHash, state.UserPinHash)
	require.True(t, state.Initialized)
	require.Equal(t, token.Info.Flags, state.Flags)
	require.Equal(t, token.Info.MaxPinLen, state.MaxPinLen)
	require.Equal(t, token.Info.MinPinLen, state.MinPinLen)
	require.Contains(t, state.Label, "TestToken")
}

func TestModuleStorage_TokenState_NotFound(t *testing.T) {
	backend := storage.NewMemory()
	s := NewModuleStorage(backend)

	// Load non-existent token state
	state, err := s.LoadTokenState(SlotID(999))
	require.NoError(t, err)
	require.Nil(t, state)
}

func TestModuleStorage_SaveObject(t *testing.T) {
	backend := storage.NewMemory()
	s := NewModuleStorage(backend)

	// Create a token object
	obj := &Object{
		Handle:        1,
		Class:         CKO_PRIVATE_KEY,
		KeyType:       CKK_RSA,
		KeyID:         "test-key-id",
		BackendName:   "software",
		IsToken:       true,
		IsPrivate:     true,
		IsSensitive:   true,
		IsExtractable: false,
		IsModifiable:  true,
		IsCopyable:    false,
		IsDestroyable: true,
		Attributes: map[AttributeType][]byte{
			CKA_LABEL: []byte("test-key"),
		},
	}

	// Save object
	err := s.SaveObject(SlotID(0), obj)
	require.NoError(t, err)

	// Load objects
	objects, err := s.LoadObjects(SlotID(0))
	require.NoError(t, err)
	require.Len(t, objects, 1)

	po := objects[0]
	require.Equal(t, uint64(1), po.Handle)
	require.Equal(t, uint32(CKO_PRIVATE_KEY), po.Class)
	require.Equal(t, uint32(CKK_RSA), po.KeyType)
	require.Equal(t, "test-key-id", po.KeyID)
	require.Equal(t, "software", po.BackendName)
	require.True(t, po.IsToken)
	require.True(t, po.IsPrivate)
	require.True(t, po.IsSensitive)
	require.False(t, po.IsExtractable)
}

// TestModuleStorage_SaveObject_SensitiveValueOmitted is a regression test for
// the security-hardening change to SaveObject: key material for a protected
// object (CKA_SENSITIVE=TRUE or CKA_EXTRACTABLE=FALSE) must never reach the
// store in the clear, while non-sensitive metadata attributes (e.g.
// CKA_LABEL) must still be persisted so the object can be found again.
func TestModuleStorage_SaveObject_SensitiveValueOmitted(t *testing.T) {
	backend := storage.NewMemory()
	s := NewModuleStorage(backend)

	obj := &Object{
		Handle:        1,
		Class:         CKO_PRIVATE_KEY,
		KeyType:       CKK_RSA,
		KeyID:         "protected-key",
		BackendName:   "software",
		IsToken:       true,
		IsPrivate:     true,
		IsSensitive:   true,
		IsExtractable: false,
		Attributes: map[AttributeType][]byte{
			CKA_LABEL:            []byte("protected-key-label"),
			CKA_VALUE:            []byte("super-secret-key-material"),
			CKA_PRIVATE_EXPONENT: []byte("secret-rsa-d"),
		},
	}

	err := s.SaveObject(SlotID(0), obj)
	require.NoError(t, err)

	objects, err := s.LoadObjects(SlotID(0))
	require.NoError(t, err)
	require.Len(t, objects, 1)

	po := objects[0]
	// Metadata describing the object must survive.
	require.Equal(t, "protected-key", po.KeyID)
	require.True(t, po.IsSensitive)
	require.False(t, po.IsExtractable)

	attrs := make(map[AttributeType][]byte, len(po.Attributes))
	for _, a := range po.Attributes {
		attrs[AttributeType(a.Type)] = a.Value
	}

	if _, ok := attrs[CKA_VALUE]; ok {
		t.Error("SaveObject persisted CKA_VALUE for a sensitive/unextractable object")
	}
	if _, ok := attrs[CKA_PRIVATE_EXPONENT]; ok {
		t.Error("SaveObject persisted CKA_PRIVATE_EXPONENT for a sensitive/unextractable object")
	}
	if got, ok := attrs[CKA_LABEL]; !ok || string(got) != "protected-key-label" {
		t.Errorf("expected CKA_LABEL to be persisted as %q, got %q (present=%v)", "protected-key-label", got, ok)
	}
}

// TestModuleStorage_SaveObject_ExtractableValuePersisted contrasts with
// TestModuleStorage_SaveObject_SensitiveValueOmitted: an object that is
// neither sensitive nor unextractable is not "protected", so its CKA_VALUE is
// persisted normally. This guards against an overly broad filter that drops
// CKA_VALUE unconditionally.
func TestModuleStorage_SaveObject_ExtractableValuePersisted(t *testing.T) {
	backend := storage.NewMemory()
	s := NewModuleStorage(backend)

	obj := &Object{
		Handle:        2,
		Class:         CKO_SECRET_KEY,
		KeyType:       CKK_AES,
		IsToken:       true,
		IsSensitive:   false,
		IsExtractable: true,
		Attributes: map[AttributeType][]byte{
			CKA_VALUE: []byte("plain-exportable-key"),
		},
	}

	err := s.SaveObject(SlotID(0), obj)
	require.NoError(t, err)

	objects, err := s.LoadObjects(SlotID(0))
	require.NoError(t, err)
	require.Len(t, objects, 1)

	po := objects[0]
	require.Len(t, po.Attributes, 1)
	require.Equal(t, uint32(CKA_VALUE), po.Attributes[0].Type)
	require.Equal(t, []byte("plain-exportable-key"), po.Attributes[0].Value)
}

func TestModuleStorage_SaveObject_SessionObject(t *testing.T) {
	backend := storage.NewMemory()
	s := NewModuleStorage(backend)

	// Create a session object (not token object)
	obj := &Object{
		Handle:  1,
		Class:   CKO_DATA,
		IsToken: false, // Session object
	}

	// Save object - should be silently ignored
	err := s.SaveObject(SlotID(0), obj)
	require.NoError(t, err)

	// Load objects - should be empty since session objects aren't persisted
	objects, err := s.LoadObjects(SlotID(0))
	require.NoError(t, err)
	require.Len(t, objects, 0)
}

func TestModuleStorage_DeleteObject(t *testing.T) {
	backend := storage.NewMemory()
	s := NewModuleStorage(backend)

	// Create and save an object
	obj := &Object{
		Handle:  1,
		Class:   CKO_SECRET_KEY,
		IsToken: true,
	}

	err := s.SaveObject(SlotID(0), obj)
	require.NoError(t, err)

	// Verify it exists
	objects, err := s.LoadObjects(SlotID(0))
	require.NoError(t, err)
	require.Len(t, objects, 1)

	// Delete the object
	err = s.DeleteObject(1)
	require.NoError(t, err)

	// Verify it's gone
	objects, err = s.LoadObjects(SlotID(0))
	require.NoError(t, err)
	require.Len(t, objects, 0)
}

func TestModuleStorage_DeleteObject_NotFound(t *testing.T) {
	backend := storage.NewMemory()
	s := NewModuleStorage(backend)

	// Delete non-existent object - should not error
	err := s.DeleteObject(999)
	require.NoError(t, err)
}

func TestModuleStorage_HandleCounter(t *testing.T) {
	backend := storage.NewMemory()
	s := NewModuleStorage(backend)

	// Get first handle
	handle1, err := s.GetNextHandle()
	require.NoError(t, err)
	require.Equal(t, ObjectHandle(1), handle1)

	// Get second handle
	handle2, err := s.GetNextHandle()
	require.NoError(t, err)
	require.Equal(t, ObjectHandle(2), handle2)

	// Set handle explicitly
	err = s.SetNextHandle(100)
	require.NoError(t, err)

	// Get next handle - should be 101
	handle3, err := s.GetNextHandle()
	require.NoError(t, err)
	require.Equal(t, ObjectHandle(101), handle3)
}

func TestModuleStorage_Close(t *testing.T) {
	backend := storage.NewMemory()
	s := NewModuleStorage(backend)

	err := s.Close()
	require.NoError(t, err)
}

func TestRestoreObject(t *testing.T) {
	po := &PersistentObject{
		Handle:        42,
		SlotID:        0,
		Class:         uint32(CKO_PUBLIC_KEY),
		KeyType:       uint32(CKK_EC),
		KeyID:         "restored-key",
		BackendName:   "tpm2",
		IsToken:       true,
		IsPrivate:     false,
		IsSensitive:   false,
		IsExtractable: true,
		IsModifiable:  true,
		IsCopyable:    true,
		IsDestroyable: true,
		Attributes: []PersistentAttribute{
			{Type: uint32(CKA_LABEL), Value: []byte("restored-label")},
			{Type: uint32(CKA_ID), Value: []byte("key-id")},
		},
	}

	obj := RestoreObject(po)

	require.Equal(t, ObjectHandle(42), obj.Handle)
	require.Equal(t, CKO_PUBLIC_KEY, obj.Class)
	require.Equal(t, CKK_EC, obj.KeyType)
	require.Equal(t, "restored-key", obj.KeyID)
	require.Equal(t, "tpm2", obj.BackendName)
	require.True(t, obj.IsToken)
	require.False(t, obj.IsPrivate)
	require.False(t, obj.IsSensitive)
	require.True(t, obj.IsExtractable)
	require.Len(t, obj.Attributes, 2)
	require.Equal(t, []byte("restored-label"), obj.Attributes[CKA_LABEL])
	require.Equal(t, []byte("key-id"), obj.Attributes[CKA_ID])
}

// TestRestoreObject_WidensLegacyULongAttributes proves that an object read back
// out of a token file written before the CK_ULONG width normalization existed is
// restored at the native width.
//
// New objects serialize their CKA_CLASS and CKA_KEY_TYPE eight bytes wide
// because Object.SetAttribute normalizes them, so only an already-persisted
// object can carry the four-byte encoding — which is precisely the upgrade
// path. If RestoreObject writes the persisted bytes into the attribute map
// directly it reinstates the defect on every existing key: C_GetAttributeValue
// reports ulValueLen 4, and an application that allocated sizeof(CK_ULONG)
// decodes the class from four bytes of value and four bytes of its own
// uninitialized buffer. This test fails the moment the restore path stops going
// through SetAttribute.
func TestRestoreObject_WidensLegacyULongAttributes(t *testing.T) {
	po := &PersistentObject{
		Handle:  7,
		Class:   uint32(CKO_PUBLIC_KEY),
		KeyType: uint32(CKK_RSA),
		Attributes: []PersistentAttribute{
			// The four-byte little-endian encoding a pre-fix token file holds.
			{Type: uint32(CKA_CLASS), Value: []byte{byte(CKO_PUBLIC_KEY), 0x00, 0x00, 0x00}},
			{Type: uint32(CKA_KEY_TYPE), Value: []byte{byte(CKK_RSA), 0x00, 0x00, 0x00}},
			{Type: uint32(CKA_MODULUS_BITS), Value: []byte{0x00, 0x08, 0x00, 0x00}},
		},
	}

	obj := RestoreObject(po)

	require.Equal(t, encodeULong(uint64(CKO_PUBLIC_KEY)), obj.Attributes[CKA_CLASS],
		"a restored CKA_CLASS must be re-encoded at the native CK_ULONG width")
	require.Equal(t, encodeULong(uint64(CKK_RSA)), obj.Attributes[CKA_KEY_TYPE],
		"a restored CKA_KEY_TYPE must be re-encoded at the native CK_ULONG width")
	require.Equal(t, encodeULong(2048), obj.Attributes[CKA_MODULUS_BITS],
		"every CK_ULONG-typed attribute is normalized on restore, not only the two "+
			"the provider happened to trip over")

	// The persisted scalars remain the authority for the convenience fields.
	require.Equal(t, ObjectHandle(7), obj.Handle)
	require.Equal(t, CKO_PUBLIC_KEY, obj.Class)
	require.Equal(t, CKK_RSA, obj.KeyType)
}

// TestRestoreObject_LeavesNonULongValuesVerbatim proves the restore path widens
// only what PKCS#11 types as a CK_ULONG, and invents no bytes.
//
// Normalizing on restore must not become "pad everything to eight bytes":
// CKA_ID and CKA_LABEL are byte arrays whose length is their content, and a
// CK_ULONG-typed attribute that was persisted at neither legal width holds a
// number this module never wrote, so widening it would put a value the caller
// never supplied into the object. This test fails if the restore path pads by
// length rather than by attribute type.
func TestRestoreObject_LeavesNonULongValuesVerbatim(t *testing.T) {
	po := &PersistentObject{
		Attributes: []PersistentAttribute{
			{Type: uint32(CKA_ID), Value: []byte{0x01, 0x02, 0x03, 0x04}},
			{Type: uint32(CKA_LABEL), Value: []byte("legacy")},
			{Type: uint32(CKA_TOKEN), Value: []byte{0x01}},
			{Type: uint32(CKA_CLASS), Value: []byte{0x02, 0x00, 0x00}},
		},
	}

	obj := RestoreObject(po)

	require.Equal(t, []byte{0x01, 0x02, 0x03, 0x04}, obj.Attributes[CKA_ID],
		"CKA_ID is a byte array; its length is its content and must survive restore")
	require.Equal(t, []byte("legacy"), obj.Attributes[CKA_LABEL],
		"CKA_LABEL is a string; restore must not pad it")
	require.Equal(t, []byte{0x01}, obj.Attributes[CKA_TOKEN],
		"CKA_TOKEN is a CK_BBOOL, one byte wide by definition")
	require.Equal(t, []byte{0x02, 0x00, 0x00}, obj.Attributes[CKA_CLASS],
		"a CK_ULONG value persisted at neither legal width is not one this module "+
			"wrote; restore must hand it back as found rather than invent the "+
			"missing bytes")
}

func TestRestoreTokenState(t *testing.T) {
	token := &Token{
		Info: TokenInfo{},
	}

	state := &PersistentTokenState{
		SlotID:      0,
		Label:       "RestoredToken",
		SOPinHash:   []byte("so-hash"),
		UserPinHash: []byte("user-hash"),
		Initialized: true,
		Flags:       CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED,
		MaxPinLen:   128,
		MinPinLen:   8,
		HardwareVersion: struct {
			Major uint8 `json:"major"`
			Minor uint8 `json:"minor"`
		}{Major: 3, Minor: 0},
		FirmwareVersion: struct {
			Major uint8 `json:"major"`
			Minor uint8 `json:"minor"`
		}{Major: 1, Minor: 5},
	}

	RestoreTokenState(token, state)

	require.Equal(t, []byte("so-hash"), token.SOPinHash)
	require.Equal(t, []byte("user-hash"), token.UserPinHash)
	require.True(t, token.Initialized)
	require.Equal(t, state.Flags, token.Info.Flags)
	require.Equal(t, uint64(128), token.Info.MaxPinLen)
	require.Equal(t, uint64(8), token.Info.MinPinLen)
	require.Equal(t, uint8(3), token.Info.HardwareVersion.Major)
	require.Equal(t, uint8(0), token.Info.HardwareVersion.Minor)
	require.Equal(t, uint8(1), token.Info.FirmwareVersion.Major)
	require.Equal(t, uint8(5), token.Info.FirmwareVersion.Minor)
}

func TestModuleStorage_LoadObjects_MultipleSlots(t *testing.T) {
	backend := storage.NewMemory()
	s := NewModuleStorage(backend)

	// Create objects for different slots
	obj1 := &Object{Handle: 1, Class: CKO_DATA, IsToken: true}
	obj2 := &Object{Handle: 2, Class: CKO_DATA, IsToken: true}
	obj3 := &Object{Handle: 3, Class: CKO_DATA, IsToken: true}

	_ = s.SaveObject(SlotID(0), obj1)
	_ = s.SaveObject(SlotID(0), obj2)
	_ = s.SaveObject(SlotID(1), obj3)

	// Load objects for slot 0
	objects0, err := s.LoadObjects(SlotID(0))
	require.NoError(t, err)
	require.Len(t, objects0, 2)

	// Load objects for slot 1
	objects1, err := s.LoadObjects(SlotID(1))
	require.NoError(t, err)
	require.Len(t, objects1, 1)

	// Load objects for slot 2 (empty)
	objects2, err := s.LoadObjects(SlotID(2))
	require.NoError(t, err)
	require.Len(t, objects2, 0)
}

// storageBlockingTestBackend is a storage.Backend whose calls never return on
// their own -- they only unblock when their context is canceled -- used to
// prove that ModuleStorage bounds every backend round-trip with a timeout
// rather than blocking a Cryptoki call (and the host application behind it)
// indefinitely.
type storageBlockingTestBackend struct{}

func (storageBlockingTestBackend) Get(ctx context.Context, key string) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (storageBlockingTestBackend) Put(ctx context.Context, key string, value []byte) error {
	<-ctx.Done()
	return ctx.Err()
}

func (storageBlockingTestBackend) PutIfAbsent(ctx context.Context, key string, value []byte) (bool, error) {
	<-ctx.Done()
	return false, ctx.Err()
}

func (storageBlockingTestBackend) Delete(ctx context.Context, key string) error {
	<-ctx.Done()
	return ctx.Err()
}

func (storageBlockingTestBackend) List(ctx context.Context, prefix string) ([]string, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (storageBlockingTestBackend) Scan(ctx context.Context, prefix string, fn func(key string, value []byte) error) error {
	<-ctx.Done()
	return ctx.Err()
}

func (storageBlockingTestBackend) Exists(ctx context.Context, key string) (bool, error) {
	<-ctx.Done()
	return false, ctx.Err()
}

func (storageBlockingTestBackend) Close() error { return nil }

// TestModuleStorage_SetTimeout_BoundsBackendCall tests that a backend which
// never responds still returns within the configured timeout, rather than
// blocking forever.
func TestModuleStorage_SetTimeout_BoundsBackendCall(t *testing.T) {
	s := NewModuleStorage(storageBlockingTestBackend{})
	s.SetTimeout(20 * time.Millisecond)

	start := time.Now()
	err := s.SaveTokenState(SlotID(0), &Token{}, 0, 0)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error from a backend that never responds")
	}
	if elapsed > 2*time.Second {
		t.Errorf("SaveTokenState took %v, expected it to be bounded by the configured timeout (20ms)", elapsed)
	}
}

// TestModuleStorage_SetTimeout_IgnoresNonPositive tests that SetTimeout
// leaves the existing timeout in place when given a non-positive value,
// matching its documented behavior, instead of disabling the bound
// altogether. This inspects the context opContext produces directly rather
// than waiting out the (10s) default timeout, so the test stays fast.
func TestModuleStorage_SetTimeout_IgnoresNonPositive(t *testing.T) {
	s := NewModuleStorage(storage.NewMemory())
	s.SetTimeout(0)
	s.SetTimeout(-5 * time.Second)

	ctx, cancel := s.opContext()
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("expected opContext() to produce a context with a deadline")
	}
	remaining := time.Until(deadline)
	if remaining <= 0 || remaining > DefaultStorageTimeout {
		t.Errorf("expected remaining timeout in (0, %v], got %v -- SetTimeout(non-positive) should leave the default in place", DefaultStorageTimeout, remaining)
	}
}

// TestModuleStorage_FailedAttemptCounter_CAS exercises the atomic counter path
// on a compare-and-swap-capable backend (the memory engine): increments
// accumulate, reset clears, and a load reads the authoritative dedicated key.
func TestModuleStorage_FailedAttemptCounter_CAS(t *testing.T) {
	s := NewModuleStorage(storage.NewMemory())
	t.Cleanup(func() { _ = s.Close() })

	// Two increments accumulate to 2 and each returns the authoritative value.
	v, persisted, err := s.IncrementFailedAttempt(0, CKU_USER)
	require.NoError(t, err)
	require.True(t, persisted)
	require.Equal(t, uint32(1), v)

	v, persisted, err = s.IncrementFailedAttempt(0, CKU_USER)
	require.NoError(t, err)
	require.True(t, persisted)
	require.Equal(t, uint32(2), v)

	// The SO counter is independent of the user counter.
	v, _, err = s.IncrementFailedAttempt(0, CKU_SO)
	require.NoError(t, err)
	require.Equal(t, uint32(1), v)

	// Load returns the dedicated-key values, ignoring the record fallback.
	user, so, err := s.LoadFailedAttempts(0, 99, 99)
	require.NoError(t, err)
	require.Equal(t, uint32(2), user)
	require.Equal(t, uint32(1), so)

	// Reset clears only the user counter.
	require.NoError(t, s.ResetFailedAttempt(0, CKU_USER))
	user, so, err = s.LoadFailedAttempts(0, 0, 0)
	require.NoError(t, err)
	require.Equal(t, uint32(0), user)
	require.Equal(t, uint32(1), so)
}

// TestModuleStorage_LoadFailedAttempts_MigratesFromRecord verifies that a token
// with no dedicated counter key seeds from the record snapshot, and that the seed
// then serves as the base for a subsequent atomic increment.
func TestModuleStorage_LoadFailedAttempts_MigratesFromRecord(t *testing.T) {
	s := NewModuleStorage(storage.NewMemory())
	t.Cleanup(func() { _ = s.Close() })

	// No dedicated key exists yet: the record snapshot (2, 1) is adopted.
	user, so, err := s.LoadFailedAttempts(0, 2, 1)
	require.NoError(t, err)
	require.Equal(t, uint32(2), user)
	require.Equal(t, uint32(1), so)

	// The seed became authoritative: the next increment builds on 2, not 0.
	v, _, err := s.IncrementFailedAttempt(0, CKU_USER)
	require.NoError(t, err)
	require.Equal(t, uint32(3), v)
}

// TestModuleStorage_FailedAttemptCounter_NilBackend confirms a store-less module
// reports persisted=false so the caller advances its own in-memory counter.
func TestModuleStorage_FailedAttemptCounter_NilBackend(t *testing.T) {
	s := NewModuleStorage(nil)

	v, persisted, err := s.IncrementFailedAttempt(0, CKU_USER)
	require.NoError(t, err)
	require.False(t, persisted)
	require.Equal(t, uint32(0), v)

	require.NoError(t, s.ResetFailedAttempt(0, CKU_USER))

	user, so, err := s.LoadFailedAttempts(0, 5, 6)
	require.NoError(t, err)
	require.Equal(t, uint32(5), user)
	require.Equal(t, uint32(6), so)
}

// TestModuleStorage_FailedAttemptCounter_ConcurrentAccumulates is the property
// the server-authoritative counter exists for: many clients incrementing one
// shared token's counter through the same CAS-capable backend must all be
// counted, with no lost updates. Two ModuleStorage instances over one backend
// model two remote-mode modules pointed at the same server-side token.
func TestModuleStorage_FailedAttemptCounter_ConcurrentAccumulates(t *testing.T) {
	backend := storage.NewMemory()
	t.Cleanup(func() { _ = backend.Close() })
	a := NewModuleStorage(backend)
	b := NewModuleStorage(backend)

	const perClient = 25
	var wg sync.WaitGroup
	wg.Add(2)
	for _, s := range []*ModuleStorage{a, b} {
		go func(store *ModuleStorage) {
			defer wg.Done()
			for i := 0; i < perClient; i++ {
				if _, _, err := store.IncrementFailedAttempt(0, CKU_USER); err != nil {
					t.Errorf("increment: %v", err)
					return
				}
			}
		}(s)
	}
	wg.Wait()

	user, _, err := a.LoadFailedAttempts(0, 0, 0)
	require.NoError(t, err)
	require.Equal(t, uint32(2*perClient), user,
		"every concurrent increment across both clients must be counted; a lower total is a lost update")
}
