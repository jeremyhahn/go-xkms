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

package oidc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// TokenStore defines the interface for persistent token storage.
type TokenStore interface {
	// Save stores tokens for the given issuer.
	Save(issuer string, tokens *TokenResponse) error

	// Load retrieves tokens for the given issuer.
	Load(issuer string) (*TokenResponse, error)

	// Delete removes tokens for the given issuer.
	Delete(issuer string) error

	// List returns all issuers with stored tokens.
	List() ([]string, error)

	// Close closes the store and releases resources.
	Close() error
}

// FileTokenStore implements TokenStore using encrypted file storage.
type FileTokenStore struct {
	path       string
	key        []byte // AES-256 encryption key
	mu         sync.RWMutex
	closed     bool
	tokens     map[string]*TokenResponse
	gcm        cipher.AEAD
	fileLoaded bool
}

// encryptedStoreData is the structure persisted to disk.
type encryptedStoreData struct {
	Tokens map[string]*encryptedToken `json:"tokens"`
}

// encryptedToken stores the encrypted token data.
type encryptedToken struct {
	Ciphertext []byte `json:"ciphertext"`
	Nonce      []byte `json:"nonce"`
}

// NewFileTokenStore creates a new file-based token store with encryption.
// The encryptionKey should be a secure key (any length, will be hashed to 32 bytes).
// If encryptionKey is nil, tokens are stored without encryption (not recommended).
func NewFileTokenStore(path string, encryptionKey []byte) (*FileTokenStore, error) {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}

	store := &FileTokenStore{
		path:   path,
		tokens: make(map[string]*TokenResponse),
	}

	// Derive a 32-byte key from the provided key using SHA-256
	if encryptionKey != nil {
		hash := sha256.Sum256(encryptionKey)
		store.key = hash[:]

		// Initialize AES-GCM cipher
		block, err := aes.NewCipher(store.key)
		if err != nil {
			return nil, ErrEncryptionFailed
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, ErrEncryptionFailed
		}
		store.gcm = gcm
	}

	// Load existing tokens if file exists
	if _, err := os.Stat(path); err == nil {
		if err := store.load(); err != nil {
			// If we can't load (e.g., wrong key), start fresh
			store.tokens = make(map[string]*TokenResponse)
		}
	}

	return store, nil
}

// Save stores tokens for the given issuer.
func (s *FileTokenStore) Save(issuer string, tokens *TokenResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStoreClosed
	}

	if issuer == "" {
		return ErrInvalidIssuer
	}

	if tokens == nil {
		return ErrTokenNotFound
	}

	// Normalize issuer
	issuer = normalizeIssuer(issuer)

	s.tokens[issuer] = tokens
	return s.save()
}

// Load retrieves tokens for the given issuer.
func (s *FileTokenStore) Load(issuer string) (*TokenResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrStoreClosed
	}

	if issuer == "" {
		return nil, ErrInvalidIssuer
	}

	// Normalize issuer
	issuer = normalizeIssuer(issuer)

	tokens, exists := s.tokens[issuer]
	if !exists {
		return nil, ErrTokenNotFound
	}

	return tokens, nil
}

// Delete removes tokens for the given issuer.
func (s *FileTokenStore) Delete(issuer string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStoreClosed
	}

	if issuer == "" {
		return ErrInvalidIssuer
	}

	// Normalize issuer
	issuer = normalizeIssuer(issuer)

	if _, exists := s.tokens[issuer]; !exists {
		return ErrTokenNotFound
	}

	delete(s.tokens, issuer)
	return s.save()
}

// List returns all issuers with stored tokens.
func (s *FileTokenStore) List() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrStoreClosed
	}

	issuers := make([]string, 0, len(s.tokens))
	for issuer := range s.tokens {
		issuers = append(issuers, issuer)
	}

	sort.Strings(issuers)
	return issuers, nil
}

// Close closes the store.
func (s *FileTokenStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	s.closed = true

	// Clear sensitive data
	for k := range s.tokens {
		delete(s.tokens, k)
	}
	s.tokens = nil

	// Clear encryption key
	if s.key != nil {
		for i := range s.key {
			s.key[i] = 0
		}
		s.key = nil
	}

	return nil
}

// load reads and decrypts tokens from the file.
func (s *FileTokenStore) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}

	if len(data) == 0 {
		return nil
	}

	var storeData encryptedStoreData
	if err := json.Unmarshal(data, &storeData); err != nil {
		return err
	}

	s.tokens = make(map[string]*TokenResponse)
	for issuer, encToken := range storeData.Tokens {
		tokens, err := s.decryptToken(encToken)
		if err != nil {
			continue // Skip tokens we can't decrypt
		}
		s.tokens[issuer] = tokens
	}

	s.fileLoaded = true
	return nil
}

// save encrypts and writes tokens to the file.
func (s *FileTokenStore) save() error {
	storeData := encryptedStoreData{
		Tokens: make(map[string]*encryptedToken),
	}

	for issuer, tokens := range s.tokens {
		encToken, err := s.encryptToken(tokens)
		if err != nil {
			return err
		}
		storeData.Tokens[issuer] = encToken
	}

	data, err := json.MarshalIndent(storeData, "", "  ")
	if err != nil {
		return err
	}

	// Write atomically
	tmpPath := s.path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return err
	}

	return os.Rename(tmpPath, s.path)
}

// encryptToken encrypts a token response.
func (s *FileTokenStore) encryptToken(tokens *TokenResponse) (*encryptedToken, error) {
	plaintext, err := json.Marshal(tokens)
	if err != nil {
		return nil, err
	}

	// If no encryption key, store plaintext (base64-encoded for consistency)
	if s.gcm == nil {
		return &encryptedToken{
			Ciphertext: plaintext,
			Nonce:      nil,
		}, nil
	}

	// Generate random nonce
	nonce := make([]byte, s.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, ErrEncryptionFailed
	}

	// Encrypt
	ciphertext := s.gcm.Seal(nil, nonce, plaintext, nil)

	return &encryptedToken{
		Ciphertext: ciphertext,
		Nonce:      nonce,
	}, nil
}

// decryptToken decrypts a token response.
func (s *FileTokenStore) decryptToken(encToken *encryptedToken) (*TokenResponse, error) {
	if encToken == nil {
		return nil, ErrTokenNotFound
	}

	var plaintext []byte

	// If no encryption key, data is stored as plaintext
	if s.gcm == nil || encToken.Nonce == nil {
		plaintext = encToken.Ciphertext
	} else {
		// Decrypt
		var err error
		plaintext, err = s.gcm.Open(nil, encToken.Nonce, encToken.Ciphertext, nil)
		if err != nil {
			return nil, ErrDecryptionFailed
		}
	}

	var tokens TokenResponse
	if err := json.Unmarshal(plaintext, &tokens); err != nil {
		return nil, ErrDecryptionFailed
	}

	return &tokens, nil
}

// normalizeIssuer normalizes an issuer URL for consistent storage.
func normalizeIssuer(issuer string) string {
	return strings.TrimSuffix(strings.ToLower(issuer), "/")
}

// MemoryTokenStore implements TokenStore using in-memory storage.
type MemoryTokenStore struct {
	mu     sync.RWMutex
	tokens map[string]*TokenResponse
	closed bool
}

// NewMemoryTokenStore creates a new in-memory token store.
func NewMemoryTokenStore() *MemoryTokenStore {
	return &MemoryTokenStore{
		tokens: make(map[string]*TokenResponse),
	}
}

// Save stores tokens for the given issuer.
func (s *MemoryTokenStore) Save(issuer string, tokens *TokenResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStoreClosed
	}

	if issuer == "" {
		return ErrInvalidIssuer
	}

	if tokens == nil {
		return ErrTokenNotFound
	}

	issuer = normalizeIssuer(issuer)
	s.tokens[issuer] = tokens
	return nil
}

// Load retrieves tokens for the given issuer.
func (s *MemoryTokenStore) Load(issuer string) (*TokenResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrStoreClosed
	}

	if issuer == "" {
		return nil, ErrInvalidIssuer
	}

	issuer = normalizeIssuer(issuer)
	tokens, exists := s.tokens[issuer]
	if !exists {
		return nil, ErrTokenNotFound
	}

	return tokens, nil
}

// Delete removes tokens for the given issuer.
func (s *MemoryTokenStore) Delete(issuer string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStoreClosed
	}

	if issuer == "" {
		return ErrInvalidIssuer
	}

	issuer = normalizeIssuer(issuer)
	if _, exists := s.tokens[issuer]; !exists {
		return ErrTokenNotFound
	}

	delete(s.tokens, issuer)
	return nil
}

// List returns all issuers with stored tokens.
func (s *MemoryTokenStore) List() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrStoreClosed
	}

	issuers := make([]string, 0, len(s.tokens))
	for issuer := range s.tokens {
		issuers = append(issuers, issuer)
	}

	sort.Strings(issuers)
	return issuers, nil
}

// Close closes the store.
func (s *MemoryTokenStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	s.closed = true
	for k := range s.tokens {
		delete(s.tokens, k)
	}
	s.tokens = nil

	return nil
}
