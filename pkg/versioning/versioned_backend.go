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

package versioning

import (
	"context"
	"crypto"
	"fmt"
	"sync"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// ErrBackendClosed is returned when operations are attempted on a closed backend.
var ErrBackendClosed = fmt.Errorf("versioned backend is closed")

// VersionedBackend wraps a types.Backend to provide versioning support for backends
// that don't natively support key versioning (TPM2, PKCS#11, etc.).
//
// Each key version is stored as a separate key in the underlying backend with
// a deterministic naming convention: "{keyID}-v{version}".
//
// The VersionStore tracks version metadata separately from key material, allowing
// version information to be persisted in any storage backend (file, database, etc.).
//
// Thread-safe: All operations are protected by a read-write mutex.
type VersionedBackend struct {
	mu           sync.RWMutex
	backend      types.Backend
	versionStore VersionStore
	closed       bool
}

// NewVersionedBackend creates a new versioned backend wrapper.
//
// Parameters:
//   - backend: The underlying Backend to wrap (handles actual key operations)
//   - versionStore: The VersionStore for tracking version metadata
//
// The versionStore can be:
//   - MemoryVersionStore for unit testing
//   - BackendVersionStore for standalone go-keychain (using storage.Backend)
//   - DragonDBVersionStore for DragonDB integration
func NewVersionedBackend(backend types.Backend, versionStore VersionStore) *VersionedBackend {
	return &VersionedBackend{
		backend:      backend,
		versionStore: versionStore,
	}
}

// Type returns the backend type identifier.
func (vb *VersionedBackend) Type() types.BackendType {
	return vb.backend.Type()
}

// Capabilities returns the capabilities of the underlying backend,
// with KeyRotation enabled since versioning provides rotation support.
func (vb *VersionedBackend) Capabilities() types.Capabilities {
	caps := vb.backend.Capabilities()
	// Enable key rotation since we provide it via versioning
	caps.KeyRotation = true
	return caps
}

// GenerateKey generates a new key with version 1.
// The key is stored in the backend with the naming convention: "{CN}-v1".
// Version metadata is recorded in the VersionStore.
func (vb *VersionedBackend) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	vb.mu.Lock()
	defer vb.mu.Unlock()

	if vb.closed {
		return nil, ErrBackendClosed
	}

	ctx := context.Background()
	keyID := attrs.CN

	// Check if key already exists
	_, err := vb.versionStore.GetCurrentVersion(ctx, keyID)
	if err == nil {
		return nil, fmt.Errorf("key %q already exists, use RotateKey to create a new version", keyID)
	}
	if err != ErrKeyNotFound {
		return nil, fmt.Errorf("failed to check existing key: %w", err)
	}

	// Create version 1
	version := uint64(1)
	backendKeyID := BackendKeyID(keyID, version)

	// Create versioned key attributes
	versionedAttrs := copyKeyAttributes(attrs)
	versionedAttrs.CN = backendKeyID

	// Generate key in underlying backend
	privKey, err := vb.backend.GenerateKey(versionedAttrs)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key in backend: %w", err)
	}

	// Record version metadata
	versionInfo := &VersionInfo{
		Version:      version,
		BackendKeyID: backendKeyID,
		Algorithm:    algorithmFromAttrs(attrs),
		State:        KeyStateEnabled,
		Created:      time.Now(),
	}

	if err := vb.versionStore.CreateVersion(ctx, keyID, versionInfo); err != nil {
		// Attempt cleanup on failure
		_ = vb.backend.DeleteKey(versionedAttrs)
		return nil, fmt.Errorf("failed to create version metadata: %w", err)
	}

	return privKey, nil
}

// GenerateKeyVersion generates a new version for an existing key.
// This is useful when you need to explicitly control the version number.
func (vb *VersionedBackend) GenerateKeyVersion(attrs *types.KeyAttributes, version uint64) (crypto.PrivateKey, error) {
	vb.mu.Lock()
	defer vb.mu.Unlock()

	if vb.closed {
		return nil, ErrBackendClosed
	}

	ctx := context.Background()
	keyID := attrs.CN
	backendKeyID := BackendKeyID(keyID, version)

	// Create versioned key attributes
	versionedAttrs := copyKeyAttributes(attrs)
	versionedAttrs.CN = backendKeyID

	// Generate key in underlying backend
	privKey, err := vb.backend.GenerateKey(versionedAttrs)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key version in backend: %w", err)
	}

	// Record version metadata
	versionInfo := &VersionInfo{
		Version:      version,
		BackendKeyID: backendKeyID,
		Algorithm:    algorithmFromAttrs(attrs),
		State:        KeyStateEnabled,
		Created:      time.Now(),
	}

	if err := vb.versionStore.CreateVersion(ctx, keyID, versionInfo); err != nil {
		// Attempt cleanup on failure
		_ = vb.backend.DeleteKey(versionedAttrs)
		return nil, fmt.Errorf("failed to create version metadata: %w", err)
	}

	return privKey, nil
}

// GetKey retrieves a key by its attributes.
// If Version is 0 (or unset), returns the current version.
// If Version is specified, returns that specific version.
func (vb *VersionedBackend) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	vb.mu.RLock()
	defer vb.mu.RUnlock()

	if vb.closed {
		return nil, ErrBackendClosed
	}

	ctx := context.Background()
	keyID := attrs.CN

	// Resolve version
	version, err := vb.resolveVersion(ctx, keyID, 0)
	if err != nil {
		return nil, err
	}

	// Get backend key ID
	backendKeyID := BackendKeyID(keyID, version)

	// Create versioned key attributes
	versionedAttrs := copyKeyAttributes(attrs)
	versionedAttrs.CN = backendKeyID

	return vb.backend.GetKey(versionedAttrs)
}

// GetKeyVersion retrieves a specific version of a key.
// If version is 0, returns the current version.
func (vb *VersionedBackend) GetKeyVersion(attrs *types.KeyAttributes, version uint64) (crypto.PrivateKey, error) {
	vb.mu.RLock()
	defer vb.mu.RUnlock()

	if vb.closed {
		return nil, ErrBackendClosed
	}

	ctx := context.Background()
	keyID := attrs.CN

	// Resolve version (0 = current)
	resolvedVersion, err := vb.resolveVersion(ctx, keyID, version)
	if err != nil {
		return nil, err
	}

	// Get backend key ID
	backendKeyID := BackendKeyID(keyID, resolvedVersion)

	// Create versioned key attributes
	versionedAttrs := copyKeyAttributes(attrs)
	versionedAttrs.CN = backendKeyID

	return vb.backend.GetKey(versionedAttrs)
}

// DeleteKey removes all versions of a key.
func (vb *VersionedBackend) DeleteKey(attrs *types.KeyAttributes) error {
	vb.mu.Lock()
	defer vb.mu.Unlock()

	if vb.closed {
		return ErrBackendClosed
	}

	ctx := context.Background()
	keyID := attrs.CN

	// Get all versions
	versions, err := vb.versionStore.ListVersions(ctx, keyID)
	if err != nil {
		return fmt.Errorf("failed to list versions: %w", err)
	}

	// Delete each version from backend
	var errs []error
	for _, v := range versions {
		versionedAttrs := copyKeyAttributes(attrs)
		versionedAttrs.CN = v.BackendKeyID

		if err := vb.backend.DeleteKey(versionedAttrs); err != nil {
			errs = append(errs, fmt.Errorf("version %d: %w", v.Version, err))
		}
	}

	// Delete version metadata
	if err := vb.versionStore.DeleteKey(ctx, keyID); err != nil {
		errs = append(errs, fmt.Errorf("metadata: %w", err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to delete key: %v", errs)
	}

	return nil
}

// DeleteKeyVersion removes a specific version of a key.
// Cannot delete the current version unless it's the only version.
func (vb *VersionedBackend) DeleteKeyVersion(attrs *types.KeyAttributes, version uint64) error {
	vb.mu.Lock()
	defer vb.mu.Unlock()

	if vb.closed {
		return ErrBackendClosed
	}

	ctx := context.Background()
	keyID := attrs.CN

	// Get version info
	versionInfo, err := vb.versionStore.GetVersionInfo(ctx, keyID, version)
	if err != nil {
		return fmt.Errorf("failed to get version info: %w", err)
	}

	// Delete from backend
	versionedAttrs := copyKeyAttributes(attrs)
	versionedAttrs.CN = versionInfo.BackendKeyID

	if err := vb.backend.DeleteKey(versionedAttrs); err != nil {
		return fmt.Errorf("failed to delete key from backend: %w", err)
	}

	// Delete version metadata
	if err := vb.versionStore.DeleteVersion(ctx, keyID, version); err != nil {
		return fmt.Errorf("failed to delete version metadata: %w", err)
	}

	return nil
}

// ListKeys returns attributes for all keys managed by this backend.
// Returns unique logical key IDs (not versioned backend key IDs).
func (vb *VersionedBackend) ListKeys() ([]*types.KeyAttributes, error) {
	vb.mu.RLock()
	defer vb.mu.RUnlock()

	if vb.closed {
		return nil, ErrBackendClosed
	}

	ctx := context.Background()

	// Get all logical key IDs from version store
	keyIDs, err := vb.versionStore.ListKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}

	// Convert to KeyAttributes (minimal info - just the key IDs)
	result := make([]*types.KeyAttributes, 0, len(keyIDs))
	for _, keyID := range keyIDs {
		result = append(result, &types.KeyAttributes{
			CN: keyID,
		})
	}

	return result, nil
}

// Signer returns a crypto.Signer for the current version of the key.
func (vb *VersionedBackend) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	return vb.SignerVersion(attrs, 0)
}

// SignerVersion returns a crypto.Signer for a specific version of the key.
// If version is 0, uses the current version.
func (vb *VersionedBackend) SignerVersion(attrs *types.KeyAttributes, version uint64) (crypto.Signer, error) {
	vb.mu.RLock()
	defer vb.mu.RUnlock()

	if vb.closed {
		return nil, ErrBackendClosed
	}

	ctx := context.Background()
	keyID := attrs.CN

	// Resolve version
	resolvedVersion, err := vb.resolveVersion(ctx, keyID, version)
	if err != nil {
		return nil, err
	}

	// Get backend key ID
	backendKeyID := BackendKeyID(keyID, resolvedVersion)

	// Create versioned key attributes
	versionedAttrs := copyKeyAttributes(attrs)
	versionedAttrs.CN = backendKeyID

	return vb.backend.Signer(versionedAttrs)
}

// Decrypter returns a crypto.Decrypter for the current version of the key.
func (vb *VersionedBackend) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	return vb.DecrypterVersion(attrs, 0)
}

// DecrypterVersion returns a crypto.Decrypter for a specific version of the key.
// If version is 0, uses the current version.
func (vb *VersionedBackend) DecrypterVersion(attrs *types.KeyAttributes, version uint64) (crypto.Decrypter, error) {
	vb.mu.RLock()
	defer vb.mu.RUnlock()

	if vb.closed {
		return nil, ErrBackendClosed
	}

	ctx := context.Background()
	keyID := attrs.CN

	// Resolve version
	resolvedVersion, err := vb.resolveVersion(ctx, keyID, version)
	if err != nil {
		return nil, err
	}

	// Get backend key ID
	backendKeyID := BackendKeyID(keyID, resolvedVersion)

	// Create versioned key attributes
	versionedAttrs := copyKeyAttributes(attrs)
	versionedAttrs.CN = backendKeyID

	return vb.backend.Decrypter(versionedAttrs)
}

// RotateKey creates a new version of the key and makes it the current version.
// The old version remains available for decryption/verification.
func (vb *VersionedBackend) RotateKey(attrs *types.KeyAttributes) error {
	vb.mu.Lock()
	defer vb.mu.Unlock()

	if vb.closed {
		return ErrBackendClosed
	}

	ctx := context.Background()
	keyID := attrs.CN

	// Get current version
	currentVersion, err := vb.versionStore.GetCurrentVersion(ctx, keyID)
	if err != nil {
		return fmt.Errorf("failed to get current version: %w", err)
	}

	// Create new version
	newVersion := currentVersion + 1
	backendKeyID := BackendKeyID(keyID, newVersion)

	// Create versioned key attributes
	versionedAttrs := copyKeyAttributes(attrs)
	versionedAttrs.CN = backendKeyID

	// Generate new key in backend
	_, err = vb.backend.GenerateKey(versionedAttrs)
	if err != nil {
		return fmt.Errorf("failed to generate rotated key: %w", err)
	}

	// Record new version metadata
	versionInfo := &VersionInfo{
		Version:      newVersion,
		BackendKeyID: backendKeyID,
		Algorithm:    algorithmFromAttrs(attrs),
		State:        KeyStateEnabled,
		Created:      time.Now(),
	}

	if err := vb.versionStore.CreateVersion(ctx, keyID, versionInfo); err != nil {
		// Attempt cleanup on failure
		_ = vb.backend.DeleteKey(versionedAttrs)
		return fmt.Errorf("failed to create version metadata: %w", err)
	}

	return nil
}

// GetCurrentVersion returns the current version number for a key.
func (vb *VersionedBackend) GetCurrentVersion(keyID string) (uint64, error) {
	vb.mu.RLock()
	defer vb.mu.RUnlock()

	if vb.closed {
		return 0, ErrBackendClosed
	}

	return vb.versionStore.GetCurrentVersion(context.Background(), keyID)
}

// GetVersionInfo returns metadata for a specific version.
// If version is 0, returns info for the current version.
func (vb *VersionedBackend) GetVersionInfo(keyID string, version uint64) (*VersionInfo, error) {
	vb.mu.RLock()
	defer vb.mu.RUnlock()

	if vb.closed {
		return nil, ErrBackendClosed
	}

	return vb.versionStore.GetVersionInfo(context.Background(), keyID, version)
}

// ListVersions returns all versions of a key.
func (vb *VersionedBackend) ListVersions(keyID string) ([]*VersionInfo, error) {
	vb.mu.RLock()
	defer vb.mu.RUnlock()

	if vb.closed {
		return nil, ErrBackendClosed
	}

	return vb.versionStore.ListVersions(context.Background(), keyID)
}

// SetCurrentVersion changes which version is the current/active version.
func (vb *VersionedBackend) SetCurrentVersion(keyID string, version uint64) error {
	vb.mu.Lock()
	defer vb.mu.Unlock()

	if vb.closed {
		return ErrBackendClosed
	}

	return vb.versionStore.SetCurrentVersion(context.Background(), keyID, version)
}

// UpdateVersionState changes the state of a specific version.
func (vb *VersionedBackend) UpdateVersionState(keyID string, version uint64, state KeyState) error {
	vb.mu.Lock()
	defer vb.mu.Unlock()

	if vb.closed {
		return ErrBackendClosed
	}

	return vb.versionStore.UpdateVersionState(context.Background(), keyID, version, state)
}

// Close releases resources held by the versioned backend.
func (vb *VersionedBackend) Close() error {
	vb.mu.Lock()
	defer vb.mu.Unlock()

	if vb.closed {
		return nil
	}

	vb.closed = true

	var errs []error

	if err := vb.versionStore.Close(); err != nil {
		errs = append(errs, fmt.Errorf("version store: %w", err))
	}

	if err := vb.backend.Close(); err != nil {
		errs = append(errs, fmt.Errorf("backend: %w", err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to close: %v", errs)
	}

	return nil
}

// Backend returns the underlying backend.
// Use with caution - direct operations bypass versioning.
func (vb *VersionedBackend) Backend() types.Backend {
	return vb.backend
}

// VersionStore returns the underlying version store.
func (vb *VersionedBackend) VersionStore() VersionStore {
	return vb.versionStore
}

// resolveVersion converts version 0 to the current version.
func (vb *VersionedBackend) resolveVersion(ctx context.Context, keyID string, version uint64) (uint64, error) {
	if version != 0 {
		// Verify version exists
		_, err := vb.versionStore.GetVersionInfo(ctx, keyID, version)
		if err != nil {
			return 0, err
		}
		return version, nil
	}

	// Get current version
	return vb.versionStore.GetCurrentVersion(ctx, keyID)
}

// copyKeyAttributes creates a shallow copy of KeyAttributes.
func copyKeyAttributes(attrs *types.KeyAttributes) *types.KeyAttributes {
	if attrs == nil {
		return nil
	}

	copy := *attrs
	return &copy
}

// algorithmFromAttrs extracts the algorithm string from key attributes.
func algorithmFromAttrs(attrs *types.KeyAttributes) string {
	if attrs.QuantumAttributes != nil {
		return string(attrs.QuantumAttributes.Algorithm)
	}
	if attrs.X25519Attributes != nil {
		return "X25519"
	}
	if attrs.SymmetricAlgorithm != "" {
		return string(attrs.SymmetricAlgorithm)
	}
	return attrs.KeyAlgorithm.String()
}

// Ensure VersionedBackend implements types.Backend.
var _ types.Backend = (*VersionedBackend)(nil)
