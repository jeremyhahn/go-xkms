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
	"testing"

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
	err := s.SaveTokenState(1, &Token{})
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
	err := s.SaveTokenState(SlotID(0), token)
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
