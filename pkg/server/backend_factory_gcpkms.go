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

//go:build gcpkms

package server

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/backend/gcpkms"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/file"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func createGCPKMSBackend(config BackendConfig) (types.KeyProvider, error) {
	projectID, _ := config.Config["project_id"].(string)
	if projectID == "" {
		return nil, &ErrConfigRequired{Field: "project_id", Backend: "GCP KMS"}
	}

	locationID, _ := config.Config["location_id"].(string)
	if locationID == "" {
		return nil, &ErrConfigRequired{Field: "location_id", Backend: "GCP KMS"}
	}

	keyRingID, _ := config.Config["key_ring_id"].(string)
	if keyRingID == "" {
		return nil, &ErrConfigRequired{Field: "key_ring_id", Backend: "GCP KMS"}
	}

	credentialsFile, _ := config.Config["credentials_file"].(string)
	credentialsJSON, _ := config.Config["credentials_json"].(string)

	// Create storage
	keyDir, ok := config.Config["key_dir"].(string)
	if !ok || keyDir == "" {
		keyDir = "/tmp/keystore/gcpkms/keys"
	}
	certDir, ok := config.Config["cert_dir"].(string)
	if !ok || certDir == "" {
		certDir = "/tmp/keystore/gcpkms/certs"
	}

	var keyStorage storage.Backend
	var err error
	if keyDir == "memory" {
		keyStorage = storage.New()
	} else {
		keyStorage, err = file.New(keyDir)
		if err != nil {
			return nil, &ErrStorageCreate{Resource: "key storage", Err: err}
		}
	}

	var certStorage storage.Backend
	if certDir == "memory" {
		certStorage = storage.New()
	} else {
		certStorage, err = file.New(certDir)
		if err != nil {
			return nil, &ErrStorageCreate{Resource: "cert storage", Err: err}
		}
	}

	gcpConfig := &gcpkms.Config{
		ProjectID:       projectID,
		LocationID:      locationID,
		KeyRingID:       keyRingID,
		CredentialsFile: credentialsFile,
		CredentialsJSON: []byte(credentialsJSON),
		KeyStorage:      keyStorage,
		CertStorage:     certStorage,
	}

	// GCP KMS backend requires a context
	ctx := context.Background()
	return gcpkms.NewBackend(ctx, gcpConfig)
}
