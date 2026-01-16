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

//go:build frost

package server

import (
	"fmt"

	"github.com/jeremyhahn/go-keychain/pkg/backend/frost"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/storage/file"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

func createFrostBackend(config BackendConfig) (types.Backend, error) {
	// Create public storage
	publicDir, ok := config.Config["public_dir"].(string)
	if !ok || publicDir == "" {
		publicDir = "/tmp/keystore/frost/public"
	}

	var publicStorage storage.Backend
	var err error
	if publicDir == "memory" {
		publicStorage = storage.New()
	} else {
		publicStorage, err = file.New(publicDir)
		if err != nil {
			return nil, fmt.Errorf("failed to create public storage: %w", err)
		}
	}

	// Get secret backend configuration
	// The secret backend should be another types.Backend (TPM2, PKCS#11, etc.)
	secretBackendName, _ := config.Config["secret_backend"].(string)
	if secretBackendName == "" {
		secretBackendName = "pkcs8" // Default to PKCS8 for secret storage
	}

	// Create secret backend
	secretBackend, err := createSecretBackendForFrost(secretBackendName, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create secret backend: %w", err)
	}

	// Parse FROST-specific configuration
	algorithm, _ := config.Config["algorithm"].(string)
	if algorithm == "" {
		algorithm = string(types.FrostAlgorithmEd25519)
	}

	participantID := uint32(1)
	if pid, ok := config.Config["participant_id"].(float64); ok {
		participantID = uint32(pid)
	} else if pid, ok := config.Config["participant_id"].(int); ok {
		participantID = uint32(pid)
	}

	threshold := 2
	if t, ok := config.Config["threshold"].(float64); ok {
		threshold = int(t)
	} else if t, ok := config.Config["threshold"].(int); ok {
		threshold = t
	}

	total := 3
	if t, ok := config.Config["total"].(float64); ok {
		total = int(t)
	} else if t, ok := config.Config["total"].(int); ok {
		total = t
	}

	enableNonceTracking := true
	if ent, ok := config.Config["enable_nonce_tracking"].(bool); ok {
		enableNonceTracking = ent
	}

	// Parse participants list
	var participants []string
	if p, ok := config.Config["participants"].([]interface{}); ok {
		for _, v := range p {
			if s, ok := v.(string); ok {
				participants = append(participants, s)
			}
		}
	}

	// Create nonce storage (optional, defaults to public storage)
	var nonceStorage storage.Backend
	if nonceDir, ok := config.Config["nonce_dir"].(string); ok && nonceDir != "" {
		if nonceDir == "memory" {
			nonceStorage = storage.New()
		} else {
			nonceStorage, err = file.New(nonceDir)
			if err != nil {
				return nil, fmt.Errorf("failed to create nonce storage: %w", err)
			}
		}
	}

	frostConfig := &frost.Config{
		PublicStorage:       publicStorage,
		SecretBackend:       secretBackend,
		Algorithm:           types.FrostAlgorithm(algorithm),
		ParticipantID:       participantID,
		DefaultThreshold:    threshold,
		DefaultTotal:        total,
		Participants:        participants,
		NonceStorage:        nonceStorage,
		EnableNonceTracking: enableNonceTracking,
	}

	return frost.NewBackend(frostConfig)
}

// createSecretBackendForFrost creates a backend for storing FROST secret shares.
// This can be any types.Backend that supports key storage.
func createSecretBackendForFrost(backendName string, config BackendConfig) (types.Backend, error) {
	// Create a sub-configuration for the secret backend
	secretConfig := BackendConfig{
		Name:    backendName,
		Type:    backendName,
		Enabled: true,
		Config:  make(map[string]interface{}),
	}

	// Copy relevant configuration from parent config
	if secretDir, ok := config.Config["secret_dir"].(string); ok {
		secretConfig.Config["key_dir"] = secretDir
	} else {
		secretConfig.Config["key_dir"] = "/tmp/keystore/frost/secrets"
	}

	// Copy any backend-specific configuration prefixed with "secret_"
	for k, v := range config.Config {
		if len(k) > 7 && k[:7] == "secret_" && k != "secret_backend" && k != "secret_dir" {
			secretConfig.Config[k[7:]] = v
		}
	}

	// Create the backend using the existing factory
	return createBackend(secretConfig)
}
