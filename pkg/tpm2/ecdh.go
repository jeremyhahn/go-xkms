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
	"fmt"
	"log/slog"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// ECDHZGen performs ECDH key agreement using TPM2_ECDH_ZGen command.
// This implements the TPM 2.0 specification Part 3, Commands, section 14.5.
//
// The operation computes Z = [privateKey]Q where:
//   - privateKey is the ECC private key stored in the TPM
//   - Q is the peer's public key point
//   - Z is the shared secret point
//
// Per NIST SP 800-56A, the shared secret is the X coordinate of Z.
// The caller is responsible for applying an appropriate KDF to derive
// the final key material.
//
// Parameters:
//   - keyAttrs: Key attributes identifying the TPM-resident ECC private key.
//     The key must be an ECC key with the decrypt attribute set.
//   - peerPublicKey: The peer's public key point (X, Y coordinates)
//   - backend: Storage backend for loading the key blobs
//
// Returns:
//   - The X coordinate of the shared secret point (raw bytes)
//   - An error if the operation fails
//
// Errors:
//   - store.ErrInvalidKeyAttributes if keyAttrs is nil
//   - store.ErrInvalidPublicKey if peerPublicKey is nil
//   - TPM errors if the ECDH_ZGen command fails
func (tpm *TPM2) ECDHZGen(
	keyAttrs *types.KeyAttributes,
	peerPublicKey *tpm2.TPMSECCPoint,
	backend store.KeyBackend) ([]byte, error) {

	if keyAttrs == nil {
		return nil, store.ErrInvalidKeyAttributes
	}
	if peerPublicKey == nil {
		return nil, store.ErrInvalidPublicKey
	}

	// Load the ECC key into the TPM
	loadResponse, err := tpm.LoadKeyPair(keyAttrs, nil, backend)
	if err != nil {
		tpm.logger.Error("failed to load ECC key for ECDH",
			slog.String("cn", keyAttrs.CN),
			slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to load key: %w", err)
	}
	defer tpm.Flush(loadResponse.ObjectHandle)

	tpm.logger.Debug("tpm: ECDHZGen - loaded key",
		slog.String("handle", fmt.Sprintf("0x%x", loadResponse.ObjectHandle)))

	// Create session for key authorization
	var auth tpm2.Session
	if keyAttrs.Password != nil && !keyAttrs.PlatformPolicy {
		auth = tpm.HMAC(keyAttrs.Password.Bytes())
	} else if keyAttrs.PlatformPolicy {
		session, closer, err := tpm.PlatformPolicySession(nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create platform policy session: %w", err)
		}
		defer func() {
			if err := closer(); err != nil {
				tpm.logger.Error("failed to close policy session", slog.String("error", err.Error()))
			}
		}()
		auth = session
	} else {
		auth = tpm.HMAC(nil)
	}

	// Execute ECDH_ZGen command
	// Per TCG TPM 2.0 specification Part 3, section 14.5:
	// TPM2_ECDH_ZGen uses the TPM-resident private key to perform
	// an ECDH operation with the provided public key point.
	response, err := tpm2.ECDHZGen{
		KeyHandle: tpm2.AuthHandle{
			Handle: loadResponse.ObjectHandle,
			Name:   loadResponse.Name,
			Auth:   auth,
		},
		InPoint: tpm2.New2B(*peerPublicKey),
	}.Execute(tpm.transport)

	if err != nil {
		tpm.logger.Error("TPM2_ECDH_ZGen failed",
			slog.String("cn", keyAttrs.CN),
			slog.String("error", err.Error()))
		return nil, fmt.Errorf("ECDH_ZGen failed: %w", err)
	}

	// Extract the shared secret point
	outPoint, err := response.OutPoint.Contents()
	if err != nil {
		return nil, fmt.Errorf("failed to get output point: %w", err)
	}

	// Per NIST SP 800-56A, the shared secret is the X coordinate
	sharedSecret := outPoint.X.Buffer

	tpm.logger.Debug("tpm: ECDHZGen - computed shared secret",
		slog.Int("length", len(sharedSecret)))

	return sharedSecret, nil
}
