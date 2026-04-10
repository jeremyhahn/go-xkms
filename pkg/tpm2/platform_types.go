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

package tpm2

import (
	"crypto/x509"
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/pin"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Re-export types from go-xkms/pkg/types for convenience

// KeyAttributes is provided by go-xkms/pkg/types
type KeyAttributes = types.KeyAttributes

// Password is provided by go-xkms/pkg/types
type Password = types.Password

// DEFAULT_PASSWORD is the default password
const DEFAULT_PASSWORD = "changeme"

// CertificateStorer interface for certificate storage operations
type CertificateStorer interface {
	Get(cn string) (*x509.Certificate, error)
	Save(cn string, cert *x509.Certificate) error
	Delete(cn string) error
}

// PlatformKeyStorer defines the interface for a TPM-backed platform key store
// that provides access to Storage Root Key (SRK) attributes, key backend,
// and integrated PIN management.
type PlatformKeyStorer interface {
	// SRKAttributes returns the Storage Root Key attributes.
	SRKAttributes() *types.KeyAttributes

	// Backend returns the key backend used by this store.
	Backend() store.KeyBackend

	// Initialize sets up the platform key store with SO and user PINs,
	// then creates the Storage Root Key (SRK).
	Initialize(soPIN, userPIN string) error

	// InitializeWithDefaults creates the Platform SRK using empty (default)
	// TPM hierarchy auth, skipping PINManager setup entirely.
	InitializeWithDefaults() error

	// IsInitialized returns true if the platform key store has been
	// initialized with PINs and SRK.
	IsInitialized() bool

	// PINManager returns the integrated PIN manager for backward compatibility.
	//
	// Deprecated: Use PINBackend() instead.
	PINManager() pin.PINManager //nolint:staticcheck // TODO: migrate to PINBackend

	// PINBackend returns the modern PIN backend for this key store.
	PINBackend() pin.PINBackend

	// PlatformPolicyEnabled returns true if TPM platform policy is enabled
	// in the key store configuration.
	PlatformPolicyEnabled() bool

	// VerifyAuth verifies the user PIN against the PlatformSRK's password auth.
	VerifyAuth(pin string) error

	// ChangeAuth changes the PlatformSRK's password auth (user PIN change).
	ChangeAuth(currentPIN, newPIN string) error

	// GetLockoutInfo returns real TPM dictionary attack lockout counters:
	// failedAttempts, maxFail, interval (seconds), and recovery (seconds).
	GetLockoutInfo() (failedAttempts, maxFail, interval, recovery int, err error)

	// DictionaryAttackLockoutReset resets the TPM DA lockout counter.
	DictionaryAttackLockoutReset(lockoutAuth []byte) error

	// IsProvisioned returns true if the TPM has been provisioned
	// (EK exists at the expected handle).
	IsProvisioned() bool

	// IsAuthReady returns true if the PlatformSRK's auth value is in a
	// known good state. Use this instead of IsInitialized when deciding
	// whether TPM2-based PIN verification is available.
	IsAuthReady() bool

	// SetAuthReady explicitly sets the auth-ready state. Called by the app
	// layer when restoring a confirmed TPM2 PIN backend from persisted config.
	SetAuthReady(ready bool)
}

// Errors
var (
	ErrCertNotFound = errors.New("certificate not found")
	ErrCorruptCopy  = errors.New("corrupt copy")
)
