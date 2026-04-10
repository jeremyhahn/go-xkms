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

	quicraftseal "github.com/jeremyhahn/go-quicraft/pkg/seal"
)

// Compile-time interface check.
var _ SealingStrategy = (*SoftwareStrategy)(nil)

// SoftwareStrategy implements SealingStrategy using password-based root key
// protection with FIPS-aware KDF selection (Argon2id or PBKDF2-SHA256).
//
// This strategy defers passphrase binding to Seal/Unseal operations, where
// the passphrase is provided via Credentials.Secret. It delegates to
// go-quicraft's DeferredSoftwareStrategy and translates ErrDecryptionFailed
// to ErrInvalidCredentials for consistent error semantics in go-xkms.
type SoftwareStrategy struct {
	inner *quicraftseal.SoftwareStrategy
}

// NewSoftwareStrategy creates a SoftwareStrategy for password-based root key
// protection. The passphrase is not required at construction time; it is
// provided via Credentials.Secret during Initialize/Unseal operations.
func NewSoftwareStrategy() *SoftwareStrategy {
	return &SoftwareStrategy{
		inner: quicraftseal.NewDeferredSoftwareStrategy(),
	}
}

// ID returns StrategySoftware.
func (s *SoftwareStrategy) ID() StrategyID { return StrategySoftware }

// Available always returns true because the software strategy has no external
// dependencies.
func (s *SoftwareStrategy) Available() bool { return true }

// HardwareBacked returns false.
func (s *SoftwareStrategy) HardwareBacked() bool { return false }

// SealRootKey derives a wrapping key from creds.Secret via the FIPS-aware KDF
// and encrypts the root key using AES-256-GCM. Delegation to go-quicraft's
// deferred SoftwareStrategy handles passphrase binding per call.
func (s *SoftwareStrategy) SealRootKey(
	ctx context.Context,
	rootKey []byte,
	creds Credentials,
) (*SealedRootKey, error) {
	return s.inner.SealRootKey(ctx, rootKey, creds)
}

// UnsealRootKey derives the wrapping key from creds.Secret and decrypts the
// root key. Decryption failures (wrong passphrase) are translated to
// ErrInvalidCredentials so upstream error mappers can return the appropriate
// status code.
func (s *SoftwareStrategy) UnsealRootKey(
	ctx context.Context,
	sealed *SealedRootKey,
	creds Credentials,
) ([]byte, error) {
	rootKey, err := s.inner.UnsealRootKey(ctx, sealed, creds)
	if err != nil {
		// A decryption failure during unseal means the passphrase was wrong.
		if errors.Is(err, quicraftseal.ErrDecryptionFailed) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}
	return rootKey, nil
}

// BarrierEncryptor returns (nil, nil) because the software strategy uses
// epoch-based HKDF DEKs managed by the barrier itself.
func (s *SoftwareStrategy) BarrierEncryptor(_ context.Context, _ []byte) (SymmetricEncrypter, error) {
	return nil, nil
}

// Close releases strategy-held resources. For the deferred strategy, this
// is effectively a no-op since no passphrase is held.
func (s *SoftwareStrategy) Close() error { return s.inner.Close() }
