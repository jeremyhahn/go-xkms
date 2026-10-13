//go:build frost

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

// Package xkms provides FROST threshold signing backend registration and factory.
//
// The FROST backend implements Flexible Round-Optimized Schnorr Threshold
// signatures for distributed key generation and threshold signing operations.
//
// This file is only compiled when the 'frost' build tag is specified.
package xkms

import (
	"context"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/frost"
	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/pkcs8"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func init() {
	RegisterBackend(BackendFROST)
	RegisterBackendFactory(BackendFROST, newFROSTKeyProvider)
}

// newFROSTKeyProvider creates a FROST threshold signing backend KeyProvider from configuration.
//
// Supported configuration keys:
//   - "threshold" (int): Minimum signers required (default: 2)
//   - "total" (int): Total number of participants (default: 3)
//   - "participant_id" (int): This node's participant ID (default: 1)
//   - "allow_plaintext_keys" (bool): When true, permits the internal PKCS#8
//     secret store to persist the FROST wrapping key without a password.
//     Defaults to false (fail-closed), the identical knob and default
//     newPKCS8KeyProvider exposes for the standalone "pkcs8" backend: set
//     true only when the storage medium is encrypted out of band (e.g. an
//     ephemeral, in-memory test backend). When false and no password is
//     configured, construction fails with pkcs8.ErrPlaintextKeyNotAllowed
//     rather than silently persisting the wrapping key in the clear.
func newFROSTKeyProvider(config map[string]interface{}) (types.KeyProvider, error) {
	allowPlaintext, _ := config["allow_plaintext_keys"].(bool)

	// Create a software PKCS#8 backend for secret key storage. Every other
	// key-persisting backend reachable through this registry (newPKCS8KeyProvider)
	// gates plaintext persistence behind this same AllowPlaintextKeys flag; FROST's
	// standalone factory previously never set it, so it failed closed
	// unconditionally (go-xkms#1237).
	secretStorage := storage.New()
	provider, err := pkcs8.NewBackend(&pkcs8.Config{
		KeyStorage:         secretStorage,
		AllowPlaintextKeys: allowPlaintext,
	})
	if err != nil {
		return nil, err
	}
	secretBackend, ok := provider.(types.SealingKeyProvider)
	if !ok {
		return nil, &frost.ConfigError{Field: "SecretBackend", Message: "PKCS#8 backend does not implement types.SealingKeyProvider"}
	}

	// Provision (idempotently) the Ed25519 private key the PKCS#8 backend's
	// Sealer derives an AES-256-GCM wrapping key from (HKDF), mirroring
	// pkg/server's ensureFrostSecretSealKey for the "pkcs8" secret_backend.
	sealKeyAttrs := frost.AsymmetricSecretSealKeyAttributes(types.StoreSoftware)
	if err := seal.EnsurePrivateSealKey(context.Background(), provider, sealKeyAttrs); err != nil {
		return nil, err
	}

	// A standalone FROST backend keeps its public state in memory, as its
	// secret store above does: nothing outlives the process.
	frostConfig := &frost.Config{
		DAOs:                    dao.NewStoreFactory(qrdbsdk.NewMemoryKVStore()),
		SecretBackend:           secretBackend,
		SecretSealKeyAttributes: sealKeyAttrs,
		DefaultThreshold:        2,
		DefaultTotal:            3,
		ParticipantID:           1,
	}

	if threshold, ok := config["threshold"].(int); ok {
		frostConfig.DefaultThreshold = threshold
	}
	if total, ok := config["total"].(int); ok {
		frostConfig.DefaultTotal = total
	}
	if pid, ok := config["participant_id"].(int); ok {
		frostConfig.ParticipantID = uint32(pid)
	}

	return frost.NewBackend(frostConfig)
}
