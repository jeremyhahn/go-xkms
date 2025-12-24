// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package virtualfido

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"golang.org/x/crypto/scrypt"
)

// Storage key prefixes for organizing data in the storage backend.
const (
	// StoragePrefixPIV is the prefix for PIV slot data.
	StoragePrefixPIV = "virtualfido/piv/"

	// StoragePrefixFIDO is the prefix for FIDO2 credential data.
	StoragePrefixFIDO = "virtualfido/fido/"

	// StoragePrefixConfig is the prefix for device configuration.
	StoragePrefixConfig = "virtualfido/config/"

	// StoragePrefixCounters is the prefix for signature counters.
	StoragePrefixCounters = "virtualfido/counters/"

	// StorageKeyDeviceState is the key for the main device state.
	StorageKeyDeviceState = "virtualfido/config/device_state"

	// scrypt parameters for key derivation
	scryptN = 32768
	scryptR = 8
	scryptP = 1
)

// StorageAdapter adapts go-keychain's storage.Backend to virtual-fido's
// ClientDataSaver interface. It provides encrypted persistence for
// FIDO2 credentials and PIV slot data.
type StorageAdapter struct {
	backend    storage.Backend
	passphrase string
	mu         sync.RWMutex

	// Cached encryption key derived from passphrase
	encryptionKey []byte
	salt          []byte
}

// NewStorageAdapter creates a new StorageAdapter.
// If backend is nil, creates an in-memory storage adapter.
// If passphrase is empty, data is stored unencrypted.
func NewStorageAdapter(backend storage.Backend, passphrase string) (*StorageAdapter, error) {
	if backend == nil {
		backend = newMemoryStorage()
	}

	adapter := &StorageAdapter{
		backend:    backend,
		passphrase: passphrase,
	}

	// Derive encryption key if passphrase is provided
	if passphrase != "" {
		if err := adapter.initEncryption(); err != nil {
			return nil, fmt.Errorf("failed to initialize encryption: %w", err)
		}
	}

	return adapter, nil
}

// initEncryption initializes the encryption key from the passphrase.
// It tries to load existing salt or generates a new one.
func (s *StorageAdapter) initEncryption() error {
	// Try to load existing salt
	saltKey := StoragePrefixConfig + "salt"
	salt, err := s.backend.Get(saltKey)
	if err != nil {
		// Generate new salt
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return fmt.Errorf("failed to generate salt: %w", err)
		}
		if err := s.backend.Put(saltKey, salt, nil); err != nil {
			return fmt.Errorf("failed to store salt: %w", err)
		}
	}

	s.salt = salt

	// Derive encryption key using scrypt
	key, err := scrypt.Key([]byte(s.passphrase), salt, scryptN, scryptR, scryptP, 32)
	if err != nil {
		return fmt.Errorf("failed to derive encryption key: %w", err)
	}

	s.encryptionKey = key
	return nil
}

// SaveData implements ClientDataSaver.SaveData.
// It encrypts and stores the FIDO device state.
func (s *StorageAdapter) SaveData(data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	encrypted, err := s.encrypt(data)
	if err != nil {
		// Log error but don't panic - this is a best-effort save
		return
	}

	if err := s.backend.Put(StorageKeyDeviceState, encrypted, nil); err != nil {
		// Log error but don't panic
		return
	}
}

// RetrieveData implements ClientDataSaver.RetrieveData.
// It retrieves and decrypts the FIDO device state.
func (s *StorageAdapter) RetrieveData() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()

	encrypted, err := s.backend.Get(StorageKeyDeviceState)
	if err != nil {
		return nil
	}

	data, err := s.decrypt(encrypted)
	if err != nil {
		return nil
	}

	return data
}

// Passphrase implements ClientDataSaver.Passphrase.
func (s *StorageAdapter) Passphrase() string {
	return s.passphrase
}

// encrypt encrypts data using AES-GCM with the derived key.
// If no encryption key is set, returns data unencrypted.
func (s *StorageAdapter) encrypt(plaintext []byte) ([]byte, error) {
	if s.encryptionKey == nil {
		return plaintext, nil
	}

	block, err := aes.NewCipher(s.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncryption, err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncryption, err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncryption, err)
	}

	// Prepend nonce to ciphertext
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// decrypt decrypts data using AES-GCM with the derived key.
// If no encryption key is set, returns data as-is.
func (s *StorageAdapter) decrypt(ciphertext []byte) ([]byte, error) {
	if s.encryptionKey == nil {
		return ciphertext, nil
	}

	block, err := aes.NewCipher(s.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryption, err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryption, err)
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("%w: ciphertext too short", ErrDecryption)
	}

	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPassphrase, err)
	}

	return plaintext, nil
}

// SavePIVSlot saves PIV slot data to storage.
func (s *StorageAdapter) SavePIVSlot(slot PIVSlot, data *SlotData) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	serialized, err := serializeSlotData(data)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStorageWrite, err)
	}

	encrypted, err := s.encrypt(serialized)
	if err != nil {
		return err
	}

	key := slot.StorageKey()
	if err := s.backend.Put(key, encrypted, nil); err != nil {
		return fmt.Errorf("%w: %v", ErrStorageWrite, err)
	}

	return nil
}

// LoadPIVSlot loads PIV slot data from storage.
func (s *StorageAdapter) LoadPIVSlot(slot PIVSlot) (*SlotData, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := slot.StorageKey()
	encrypted, err := s.backend.Get(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSlotNotFound, err)
	}

	decrypted, err := s.decrypt(encrypted)
	if err != nil {
		return nil, err
	}

	data, err := deserializeSlotData(decrypted)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStorageRead, err)
	}

	return data, nil
}

// DeletePIVSlot removes PIV slot data from storage.
func (s *StorageAdapter) DeletePIVSlot(slot PIVSlot) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := slot.StorageKey()
	if err := s.backend.Delete(key); err != nil {
		return fmt.Errorf("%w: %v", ErrStorageWrite, err)
	}

	return nil
}

// ListPIVSlots returns all PIV slots that have stored data.
func (s *StorageAdapter) ListPIVSlots() ([]PIVSlot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	keys, err := s.backend.List(StoragePrefixPIV + "slots/")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStorageRead, err)
	}

	slots := make([]PIVSlot, 0, len(keys))
	for _, key := range keys {
		// Extract slot byte from key (e.g., "piv/slots/9a" -> 0x9a)
		if len(key) >= 2 {
			var slotByte byte
			_, err := fmt.Sscanf(key[len(key)-2:], "%02x", &slotByte)
			if err == nil {
				if slot, err := SlotFromByte(slotByte); err == nil {
					slots = append(slots, slot)
				}
			}
		}
	}

	return slots, nil
}

// SaveConfig saves a configuration value.
func (s *StorageAdapter) SaveConfig(name string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := StoragePrefixConfig + name
	encrypted, err := s.encrypt(value)
	if err != nil {
		return err
	}

	if err := s.backend.Put(key, encrypted, nil); err != nil {
		return fmt.Errorf("%w: %v", ErrStorageWrite, err)
	}

	return nil
}

// LoadConfig loads a configuration value.
func (s *StorageAdapter) LoadConfig(name string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := StoragePrefixConfig + name
	encrypted, err := s.backend.Get(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStorageRead, err)
	}

	return s.decrypt(encrypted)
}

// Close releases resources held by the storage adapter.
func (s *StorageAdapter) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Clear sensitive data
	if s.encryptionKey != nil {
		for i := range s.encryptionKey {
			s.encryptionKey[i] = 0
		}
		s.encryptionKey = nil
	}

	return s.backend.Close()
}

// serializedSlotData is the JSON-serializable form of SlotData.
type serializedSlotData struct {
	PrivateKeyPKCS8 []byte `json:"private_key"`
	CertificateDER  []byte `json:"certificate,omitempty"`
	Algorithm       int    `json:"algorithm"`
	CreatedAt       int64  `json:"created_at"`
	TouchPolicy     uint8  `json:"touch_policy"`
	PINPolicy       uint8  `json:"pin_policy"`
}

func serializeSlotData(data *SlotData) ([]byte, error) {
	// This is a placeholder - actual implementation would use PKCS#8 encoding
	// For now, we'll use a simple JSON representation
	sd := &serializedSlotData{
		Algorithm:   int(data.Algorithm),
		CreatedAt:   data.CreatedAt.Unix(),
		TouchPolicy: uint8(data.TouchPolicy),
		PINPolicy:   uint8(data.PINPolicy),
	}

	if data.Certificate != nil {
		sd.CertificateDER = data.Certificate.Raw
	}

	return json.Marshal(sd)
}

func deserializeSlotData(data []byte) (*SlotData, error) {
	// This is a placeholder - actual implementation would parse PKCS#8
	// For now, we'll use a simple JSON representation
	var sd serializedSlotData
	if err := json.Unmarshal(data, &sd); err != nil {
		return nil, err
	}

	// Parse certificate if present
	// Parse private key
	// This is simplified - full implementation needed

	return &SlotData{
		Algorithm:   x509.PublicKeyAlgorithm(sd.Algorithm),
		TouchPolicy: TouchPolicy(sd.TouchPolicy),
		PINPolicy:   PINPolicy(sd.PINPolicy),
	}, nil
}

// memoryStorage provides an in-memory storage.Backend implementation.
type memoryStorage struct {
	data map[string][]byte
	mu   sync.RWMutex
}

func newMemoryStorage() *memoryStorage {
	return &memoryStorage{
		data: make(map[string][]byte),
	}
}

func (m *memoryStorage) Get(key string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	data, ok := m.data[key]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", key)
	}

	// Return a copy to prevent modification
	result := make([]byte, len(data))
	copy(result, data)
	return result, nil
}

func (m *memoryStorage) Put(key string, value []byte, opts *storage.Options) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Store a copy to prevent modification
	data := make([]byte, len(value))
	copy(data, value)
	m.data[key] = data
	return nil
}

func (m *memoryStorage) Delete(key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.data, key)
	return nil
}

func (m *memoryStorage) List(prefix string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var keys []string
	for key := range m.data {
		if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

func (m *memoryStorage) Exists(key string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, ok := m.data[key]
	return ok, nil
}

func (m *memoryStorage) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Clear all data
	for key := range m.data {
		delete(m.data, key)
	}
	return nil
}
