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
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/go-tpm/tpm2"
)

var (
	// ErrAuthFailed is returned when TPM auth verification fails because
	// the provided auth value does not match the key's UserAuth.
	ErrAuthFailed = errors.New("tpm2: auth verification failed")

	// ErrAuthChangeKeyNotFound is returned when the persistent handle
	// does not exist during an auth verification or change operation.
	ErrAuthChangeKeyNotFound = errors.New("tpm2: key not found at handle for auth change")

	// ErrAuthChangeRecreate is returned when the primary key cannot be
	// recreated with the new auth value during a ChangeAuth operation.
	ErrAuthChangeRecreate = errors.New("tpm2: failed to recreate primary key with new auth")
)

// VerifyAuth verifies the auth value on a persistent key at the given handle.
// The TPM validates the auth by executing a Create command with the key as
// parent. If the auth value is incorrect, the TPM returns an auth failure.
func (tpm *TPM2) VerifyAuth(handle tpm2.TPMHandle, authValue []byte) error {
	if tpm.transport == nil {
		return ErrTransportNotInitialized
	}

	// Read the public area to confirm the handle exists.
	name, _, err := tpm.ReadHandle(handle)
	if err != nil {
		return errors.Join(ErrAuthChangeKeyNotFound, err)
	}

	// Create an HMAC session with the provided auth value.
	session := tpm.HMAC(authValue)

	// Create a minimal keyed-hash child under this handle. The TPM requires
	// correct parent auth for the Create command. If the auth is wrong,
	// the TPM immediately returns TPM_RC_BAD_AUTH or TPM_RC_AUTH_FAIL.
	_, err = tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: handle,
			Name:   name,
			Auth:   session,
		},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgKeyedHash,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:     true,
				FixedParent:  true,
				UserWithAuth: true,
			},
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgKeyedHash,
				&tpm2.TPMSKeyedHashParms{
					Scheme: tpm2.TPMTKeyedHashScheme{
						Scheme: tpm2.TPMAlgNull,
					},
				},
			),
		}),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{},
		},
	}.Execute(tpm.transport)
	if err != nil {
		if isTPMAuthError(err) {
			return ErrAuthFailed
		}
		return err
	}

	// Auth verified successfully. The ephemeral child is not persisted
	// and will be garbage collected by the TPM.
	return nil
}

// ChangeAuth changes the auth value on a persistent primary key. For primary
// keys, this recreates the key with the same template (deterministic key
// material) and new auth, then evicts the old key and re-persists at the
// same handle.
func (tpm *TPM2) ChangeAuth(handle tpm2.TPMHandle, currentAuth, newAuth []byte) error {
	if tpm.transport == nil {
		return ErrTransportNotInitialized
	}

	// Verify the current auth before proceeding.
	if err := tpm.VerifyAuth(handle, currentAuth); err != nil {
		return err
	}

	// Read the public area to get the key template for recreation.
	name, pub, err := tpm.ReadHandle(handle)
	if err != nil {
		return errors.Join(ErrAuthChangeKeyNotFound, err)
	}

	// Determine the hierarchy from the persistent handle range.
	// Handles in 0x81000000-0x817FFFFF are owner hierarchy.
	// Handles in 0x81800000-0x81FFFFFF are platform hierarchy.
	hierarchy := tpm2.TPMRHOwner
	if uint32(handle) >= 0x81800000 {
		hierarchy = tpm2.TPMRHPlatform
	}

	// Evict the current persistent key.
	_, err = tpm2.EvictControl{
		Auth: tpm2.AuthHandle{
			Handle: hierarchy,
			Auth:   tpm2.PasswordAuth(nil),
		},
		ObjectHandle: &tpm2.NamedHandle{
			Handle: handle,
			Name:   name,
		},
		PersistentHandle: handle,
	}.Execute(tpm.transport)
	if err != nil {
		return errors.Join(ErrAuthChangeRecreate, fmt.Errorf("evict old handle 0x%x: %w", handle, err))
	}

	// Recreate the primary with the same template but new auth.
	// Using the same template ensures deterministic key material
	// (same hierarchy seed + same template = same key).
	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: hierarchy,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(pub),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: newAuth,
				},
			},
		},
	}.Execute(tpm.transport)
	if err != nil {
		return errors.Join(ErrAuthChangeRecreate, fmt.Errorf("recreate primary: %w", err))
	}
	defer tpm.Flush(primaryKey.ObjectHandle)

	// Persist the recreated key at the same handle.
	_, err = tpm2.EvictControl{
		Auth: tpm2.AuthHandle{
			Handle: hierarchy,
			Auth:   tpm2.PasswordAuth(nil),
		},
		ObjectHandle: &tpm2.NamedHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
		},
		PersistentHandle: handle,
	}.Execute(tpm.transport)
	if err != nil {
		return errors.Join(ErrAuthChangeRecreate, fmt.Errorf("persist new key at 0x%x: %w", handle, err))
	}

	tpm.logger.Info("auth changed for persistent handle",
		slog.String("handle", fmt.Sprintf("0x%x", handle)))

	return nil
}

// isTPMAuthError checks whether a TPM error indicates an authentication
// failure. The TPM returns specific response codes for auth failures:
//   - TPM_RC_BAD_AUTH (0x022) - authorization value is incorrect
//   - TPM_RC_AUTH_FAIL (0x09A) - authorization failed (DA counter incremented)
//   - TPM_RC_LOCKOUT (0x921) - DA lockout is active
//
// The function checks both the typed TPMRC value and the error string
// for robustness across different go-tpm versions.
func isTPMAuthError(err error) bool {
	if err == nil {
		return false
	}

	// Check typed TPM response code.
	var rc tpm2.TPMRC
	if errors.As(err, &rc) {
		// Mask out format-one session/parameter bits to get the base code.
		rcVal := uint32(rc) & 0x0FF
		if rcVal == 0x022 || rcVal == 0x09A {
			return true
		}
		// Also check the full value for format-zero codes.
		rcFull := uint32(rc) & 0xFFF
		if rcFull == 0x921 { // TPM_RC_LOCKOUT
			return true
		}
	}

	// Fall back to string matching for robustness.
	s := err.Error()
	return strings.Contains(s, "bad_auth") ||
		strings.Contains(s, "auth_fail") ||
		strings.Contains(s, "BAD_AUTH") ||
		strings.Contains(s, "AUTH_FAIL") ||
		strings.Contains(s, "TPM_RC_BAD_AUTH") ||
		strings.Contains(s, "TPM_RC_AUTH_FAIL")
}
