//go:build gcpkms

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

// Package xkms provides Google Cloud KMS backend registration and factory.
//
// The GCP KMS backend integrates with Google Cloud Key Management Service
// for cloud-based key storage and cryptographic operations.
//
// This file is only compiled when the 'gcpkms' build tag is specified.
package xkms

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/backend/gcpkms"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func init() {
	RegisterBackend(BackendGCPKMS)
	RegisterBackendFactory(BackendGCPKMS, newGCPKMSKeyProvider)
}

// newGCPKMSKeyProvider creates a GCP KMS backend KeyProvider from configuration.
//
// Supported configuration keys:
//   - "project_id" (string): GCP project ID (required)
//   - "location_id" (string): GCP location/region (required)
//   - "key_ring_id" (string): Key ring identifier (required)
//   - "credentials_file" (string): Path to service account JSON key file (optional)
//   - "endpoint" (string): Custom KMS API endpoint (optional)
func newGCPKMSKeyProvider(config map[string]interface{}) (types.KeyProvider, error) {
	gcpConfig := &gcpkms.Config{
		KeyStorage: storage.New(),
	}

	if projectID, ok := config["project_id"].(string); ok {
		gcpConfig.ProjectID = projectID
	}
	if locationID, ok := config["location_id"].(string); ok {
		gcpConfig.LocationID = locationID
	}
	if keyRingID, ok := config["key_ring_id"].(string); ok {
		gcpConfig.KeyRingID = keyRingID
	}
	if credFile, ok := config["credentials_file"].(string); ok {
		gcpConfig.CredentialsFile = credFile
	}
	if endpoint, ok := config["endpoint"].(string); ok {
		gcpConfig.Endpoint = endpoint
	}

	return gcpkms.NewBackend(context.Background(), gcpConfig)
}
