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

package ssh

import (
	"context"

	sshbackend "github.com/jeremyhahn/go-xkms/pkg/ssh/backend"
	pkgkeys "github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// BackendProvider is the capability that mints and signs backend-backed SSH
// keys. It is supplied to EmbeddedOptions.BackendProvider to enable
// hardware-backed key generation. Re-exported here so SDK consumers (the xkey
// GUI/CLI, the server composition) never import pkg/ssh/* directly.
type BackendProvider = pkgkeys.BackendProvider

// KeyProviderResolver returns the crypto KeyProvider for a backend registry ID.
// Consumers wrap their backend lookup (e.g. xkms.GetBackend(id).KeyProvider()).
type KeyProviderResolver func(ctx context.Context, backendID string) (types.KeyProvider, error)

// NewBackendProvider builds a BackendProvider from a resolver that yields the
// crypto KeyProvider for a backend ID. The resulting provider generates and
// signs SSH keys on whichever backend the caller selects; for hardware
// backends the private key never leaves the device.
func NewBackendProvider(resolve KeyProviderResolver) (BackendProvider, error) {
	return sshbackend.New(sshbackend.ResolverFunc(resolve))
}

// SupportedAlgorithms returns the canonical SSH algorithm identifiers
// ("ed25519", "rsa", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521") that a backend
// of the given category can generate. category is a backend-registry
// category string (e.g. "software", "tpm2", "pkcs11", "phone"); an unknown or
// empty category — including a remote xkms backend, whose concrete backend
// type is not known client-side — fails open to the full algorithm set: the
// backend itself remains authoritative and GenerateKey returns its own typed
// error when an algorithm is actually unsupported.
//
// This is the single source of truth for algorithm compatibility, derived
// from each backend's GenerateKey implementation (see
// sshbackend.SupportedAlgorithms), and is re-exported here so SDK consumers
// (the xkey GUI generate dialog, the CLI) never import pkg/ssh/* directly and
// can never drift from one another.
func SupportedAlgorithms(category string) []string {
	algos := sshbackend.SupportedAlgorithms(types.ParseStoreType(category))
	out := make([]string, len(algos))
	for i, a := range algos {
		out[i] = string(a)
	}
	return out
}
