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

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
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

	// Initialize sets up the platform key store with the owner hierarchy
	// auth and the user PIN, then creates the Storage Root Key (SRK).
	Initialize(soPIN, userPIN string) error

	// EnrollPlatformSRK performs a one-shot first-boot enrollment of the
	// Platform SRK, binding the operator-supplied userPIN as its auth value.
	// soPIN is the TPM owner hierarchy authorization value, required whenever
	// the hierarchy carries one, because the Platform SRK is a persistent
	// object in that hierarchy; pass an empty string when it has none.
	// It is idempotent: ErrPlatformSRKAlreadyEnrolled is returned when the
	// SRK auth is already in a known-good state.
	EnrollPlatformSRK(soPIN, userPIN string) error

	// InitializeWithDefaults creates the Platform SRK using empty (default)
	// TPM hierarchy auth, skipping PINManager setup entirely.
	InitializeWithDefaults() error

	// IsInitialized returns true if the platform key store has been
	// initialized with PINs and SRK.
	IsInitialized() bool

	// PINBackend returns the canonical PIN backend for this key store
	// (qrdb/pkg/qrdbsdk.PINBackend implemented by xkms/pkg/pintpm2.TPM2Backend).
	PINBackend() qrdbsdk.PINBackend

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

	// SetAuthReady explicitly sets the auth-ready state, for a caller that
	// has confirmed the SRK's auth value by other means. Persisted
	// configuration is not such a means: a recorded PIN strategy says which
	// backend was chosen before, not that this session confirmed the auth.
	// VerifyAuth and ChangeAuth set this themselves on success.
	SetAuthReady(ready bool)
}

// Errors
var (
	ErrCertNotFound = errors.New("certificate not found")
	ErrCorruptCopy  = errors.New("corrupt copy")
)
