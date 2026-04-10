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
	"fmt"
	"strconv"
	"sync"

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
	SlotID          uint64    `json:"slot_id"`
	Label           string    `json:"label"`
	SOPinHash       []byte    `json:"so_pin_hash"`
	UserPinHash     []byte    `json:"user_pin_hash"`
	Initialized     bool      `json:"initialized"`
	Flags           TokenFlag `json:"flags"`
	ManufacturerID  string    `json:"manufacturer_id"`
	Model           string    `json:"model"`
	SerialNumber    string    `json:"serial_number"`
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
}

// NewModuleStorage creates a new storage instance with the given backend.
func NewModuleStorage(backend storage.Backend) *ModuleStorage {
	return &ModuleStorage{
		backend: backend,
	}
}

// SaveTokenState persists the token state for a slot.
func (s *ModuleStorage) SaveTokenState(slotID SlotID, token *Token) error {
	if s.backend == nil {
		return nil // No persistence configured
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	state := &PersistentTokenState{
		SlotID:      uint64(slotID),
		SOPinHash:   token.SOPinHash,
		UserPinHash: token.UserPinHash,
		Initialized: token.Initialized,
		Flags:       token.Info.Flags,
		MaxPinLen:   token.Info.MaxPinLen,
		MinPinLen:   token.Info.MinPinLen,
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
		return fmt.Errorf("failed to marshal token state: %w", err)
	}

	key := prefixToken + strconv.FormatUint(uint64(slotID), 10)
	if err := s.backend.Put(context.Background(), key, data); err != nil {
		return fmt.Errorf("failed to save token state: %w", err)
	}

	return nil
}

// LoadTokenState loads the token state for a slot.
func (s *ModuleStorage) LoadTokenState(slotID SlotID) (*PersistentTokenState, error) {
	if s.backend == nil {
		return nil, nil // No persistence configured
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	key := prefixToken + strconv.FormatUint(uint64(slotID), 10)
	data, err := s.backend.Get(context.Background(), key)
	if err != nil {
		if err == storage.ErrNotFound {
			return nil, nil // Token not initialized yet
		}
		return nil, fmt.Errorf("failed to load token state: %w", err)
	}

	var state PersistentTokenState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token state: %w", err)
	}

	return &state, nil
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

	// Convert attributes map to slice
	po.Attributes = make([]PersistentAttribute, 0, len(obj.Attributes))
	for attrType, value := range obj.Attributes {
		po.Attributes = append(po.Attributes, PersistentAttribute{
			Type:  uint32(attrType),
			Value: value,
		})
	}

	data, err := json.Marshal(po)
	if err != nil {
		return fmt.Errorf("failed to marshal object: %w", err)
	}

	key := prefixObject + strconv.FormatUint(uint64(obj.Handle), 10)
	if err := s.backend.Put(context.Background(), key, data); err != nil {
		return fmt.Errorf("failed to save object: %w", err)
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

	keys, err := s.backend.List(context.Background(), prefixObject)
	if err != nil {
		return nil, fmt.Errorf("failed to list objects: %w", err)
	}

	var objects []*PersistentObject
	for _, key := range keys {
		data, err := s.backend.Get(context.Background(), key)
		if err != nil {
			continue // Skip objects that fail to load
		}

		var po PersistentObject
		if err := json.Unmarshal(data, &po); err != nil {
			continue // Skip objects that fail to unmarshal
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
	if err := s.backend.Delete(context.Background(), key); err != nil && err != storage.ErrNotFound {
		return fmt.Errorf("failed to delete object: %w", err)
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
	data, err := s.backend.Get(context.Background(), key)
	if err != nil && err != storage.ErrNotFound {
		return 0, fmt.Errorf("failed to get handle counter: %w", err)
	}

	var counter uint64 = 1
	if len(data) > 0 {
		counter, _ = strconv.ParseUint(string(data), 10, 64)
		counter++
	}

	if err := s.backend.Put(context.Background(), key, []byte(strconv.FormatUint(counter, 10))); err != nil {
		return 0, fmt.Errorf("failed to save handle counter: %w", err)
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
	if err := s.backend.Put(context.Background(), key, []byte(strconv.FormatUint(uint64(handle), 10))); err != nil {
		return fmt.Errorf("failed to save handle counter: %w", err)
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
func RestoreObject(po *PersistentObject) *Object {
	obj := &Object{
		Handle:        ObjectHandle(po.Handle),
		Class:         ObjectClass(po.Class),
		KeyType:       KeyType(po.KeyType),
		Attributes:    make(map[AttributeType][]byte),
		KeyID:         po.KeyID,
		BackendName:   po.BackendName,
		IsToken:       po.IsToken,
		IsPrivate:     po.IsPrivate,
		IsSensitive:   po.IsSensitive,
		IsExtractable: po.IsExtractable,
		IsModifiable:  po.IsModifiable,
		IsCopyable:    po.IsCopyable,
		IsDestroyable: po.IsDestroyable,
	}

	// Restore attributes
	for _, attr := range po.Attributes {
		obj.Attributes[AttributeType(attr.Type)] = attr.Value
	}

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

	// Copy strings to fixed-size arrays
	copy(token.Info.Label[:], state.Label)
	copy(token.Info.ManufacturerID[:], state.ManufacturerID)
	copy(token.Info.Model[:], state.Model)
	copy(token.Info.SerialNumber[:], state.SerialNumber)
}
