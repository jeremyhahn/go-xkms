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

package seal

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// Well-known secret names for platform credentials.
const (
	// SecretUserPIN is the well-known key for a user PIN credential.
	SecretUserPIN = "platform/user-pin"

	// SecretLUKSPassphrase is the well-known key for a LUKS passphrase.
	SecretLUKSPassphrase = "platform/luks-passphrase"

	// SecretPKCS11PIN is the well-known key for a PKCS#11 token PIN.
	SecretPKCS11PIN = "platform/pkcs11-pin"

	// SecretTPM2Auth is the well-known key for a TPM 2.0 auth value.
	SecretTPM2Auth = "platform/tpm2-auth"
)

// platformStorePrefix is the storage key prefix for all platform store secrets.
// This provides namespace isolation from other data in the same backend.
const platformStorePrefix = "platform-store/"

// PlatformStore provides a named-secret API for storing and retrieving
// sealed credentials. Secrets are transparently sealed and unsealed
// through the underlying backend. When the backend is a sealed.Backend,
// a Get call automatically unseals if the backend's sealer allows it
// (e.g., TPM PCR state matches). When the backend is a plain memory or
// file backend, values are stored and retrieved as-is.
type PlatformStore interface {
	// Put stores a secret under the given name. If a secret already exists
	// with this name it is overwritten with a fresh seal operation.
	Put(ctx context.Context, name string, secret []byte) error

	// Get retrieves and unseals the secret stored under the given name.
	// Returns ErrSecretNotFound if the name does not exist.
	Get(ctx context.Context, name string) ([]byte, error)

	// Delete removes the secret stored under the given name.
	// Returns ErrSecretNotFound if the name does not exist.
	Delete(ctx context.Context, name string) error

	// Exists reports whether a secret with the given name is stored.
	Exists(ctx context.Context, name string) (bool, error)

	// List returns the names of all stored secrets (without the internal
	// storage prefix).
	List(ctx context.Context) ([]string, error)

	// Reseal reads the current plaintext of a secret, deletes the old
	// sealed copy, and writes it back so it is sealed with the current
	// backend state (e.g., fresh TPM PCR values). Returns ErrResealFailed
	// wrapping the underlying cause on any failure.
	Reseal(ctx context.Context, name string) error
}

// Compile-time interface check.
var _ PlatformStore = (*SealedPlatformStore)(nil)

// SealedPlatformStore implements PlatformStore on top of a storage.Backend.
// The backend may be a sealed.Backend for transparent encryption, or a plain
// file/memory backend for testing. All operations are protected by a
// read-write mutex for concurrent safety.
type SealedPlatformStore struct {
	mu      sync.RWMutex
	backend storage.Backend
	logger  *slog.Logger
}

// NewPlatformStore creates a PlatformStore backed by the given storage.Backend.
// The backend must not be nil. If logger is nil, slog.Default() is used.
func NewPlatformStore(backend storage.Backend, logger *slog.Logger) (*SealedPlatformStore, error) {
	if backend == nil {
		return nil, ErrNilSealedBackend
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &SealedPlatformStore{
		backend: backend,
		logger:  logger.With("component", "platform_store"),
	}, nil
}

// Put stores a secret under the given name, sealing it through the backend.
func (s *SealedPlatformStore) Put(ctx context.Context, name string, secret []byte) error {
	if err := validateSecretName(name); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.backend.Put(ctx, platformStorePrefix+name, secret); err != nil {
		return fmt.Errorf("seal: put %q: %w", name, err)
	}
	s.logger.DebugContext(ctx, "secret stored", "name", name)
	return nil
}

// Get retrieves and transparently unseals the secret with the given name.
// Auto-unseal is implicit: if the backend is a sealed.Backend, unsealing
// happens transparently during the read.
func (s *SealedPlatformStore) Get(ctx context.Context, name string) ([]byte, error) {
	if err := validateSecretName(name); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	plaintext, err := s.backend.Get(ctx, platformStorePrefix+name)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrSecretNotFound
		}
		return nil, fmt.Errorf("seal: get %q: %w", name, err)
	}
	s.logger.DebugContext(ctx, "secret retrieved", "name", name)
	return plaintext, nil
}

// Delete removes the secret with the given name from the store.
func (s *SealedPlatformStore) Delete(ctx context.Context, name string) error {
	if err := validateSecretName(name); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.backend.Delete(ctx, platformStorePrefix+name); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return ErrSecretNotFound
		}
		return fmt.Errorf("seal: delete %q: %w", name, err)
	}
	s.logger.DebugContext(ctx, "secret deleted", "name", name)
	return nil
}

// Exists reports whether a secret with the given name exists in the store.
func (s *SealedPlatformStore) Exists(ctx context.Context, name string) (bool, error) {
	if err := validateSecretName(name); err != nil {
		return false, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	exists, err := s.backend.Exists(ctx, platformStorePrefix+name)
	if err != nil {
		return false, fmt.Errorf("seal: exists %q: %w", name, err)
	}
	return exists, nil
}

// List returns the names of all secrets currently stored, with the internal
// storage prefix stripped.
func (s *SealedPlatformStore) List(ctx context.Context) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	keys, err := s.backend.List(ctx, platformStorePrefix)
	if err != nil {
		return nil, fmt.Errorf("seal: list: %w", err)
	}
	names := make([]string, 0, len(keys))
	for _, key := range keys {
		names = append(names, strings.TrimPrefix(key, platformStorePrefix))
	}
	return names, nil
}

// Reseal reads the current plaintext, deletes the old sealed copy, and
// writes it back so it is sealed with the current backend state.
// This is used to refresh PCR-bound seals after system state changes.
func (s *SealedPlatformStore) Reseal(ctx context.Context, name string) error {
	if err := validateSecretName(name); err != nil {
		return fmt.Errorf("%w: %w", ErrResealFailed, err)
	}

	plaintext, err := s.Get(ctx, name)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrResealFailed, err)
	}

	if err := s.Delete(ctx, name); err != nil {
		return fmt.Errorf("%w: %w", ErrResealFailed, err)
	}

	if err := s.Put(ctx, name, plaintext); err != nil {
		return fmt.Errorf("%w: %w", ErrResealFailed, err)
	}

	s.logger.InfoContext(ctx, "secret resealed", "name", name)
	return nil
}

// validateSecretName checks that the name is non-empty after trimming whitespace.
func validateSecretName(name string) error {
	if strings.TrimSpace(name) == "" {
		return ErrInvalidSecretName
	}
	return nil
}
