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
	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/frost"
	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/pkcs8"
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
func newFROSTKeyProvider(config map[string]interface{}) (types.KeyProvider, error) {
	// Create a software PKCS#8 backend for secret key storage
	secretStorage := storage.New()
	secretBackend, err := pkcs8.NewBackend(&pkcs8.Config{
		KeyStorage: secretStorage,
	})
	if err != nil {
		return nil, err
	}

	frostConfig := &frost.Config{
		PublicStorage:    storage.New(),
		SecretBackend:    secretBackend,
		DefaultThreshold: 2,
		DefaultTotal:     3,
		ParticipantID:    1,
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
