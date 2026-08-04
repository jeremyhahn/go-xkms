// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package keys

import (
	"context"
	"crypto"
)

// BackendProvider is the minimal capability the keys package needs to mint
// and sign SSH keys whose private material lives in an external crypto
// backend (software / tpm2 / pkcs11 / cloud KMS / remote xkms). The private
// key never crosses this boundary — only a crypto.Signer is returned, so
// hardware-held keys stay in the device.
//
// The production implementation lives in pkg/ssh/backend (over an
// xkms types.KeyProvider); tests supply an in-memory fake. Defining the
// interface here keeps pkg/ssh/keys decoupled from pkg/xkms and avoids an
// import cycle.
type BackendProvider interface {
	// GenerateKey creates a key of algo (rsaBits applies only to
	// AlgorithmRSA) on backendID, stored under keyID, and returns a
	// crypto.Signer bound to the freshly generated private key.
	GenerateKey(ctx context.Context, backendID, keyID string, algo Algorithm, rsaBits int) (crypto.Signer, error)

	// Signer resolves a crypto.Signer for an existing backend-backed key
	// identified by (backendID, keyID). algo lets the backend reconstruct
	// the key attributes needed to locate the key.
	Signer(ctx context.Context, backendID, keyID string, algo Algorithm) (crypto.Signer, error)
}
