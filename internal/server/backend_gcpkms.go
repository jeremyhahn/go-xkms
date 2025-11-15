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

//go:build gcpkms

package server

import (
	"context"
	"fmt"

	"github.com/jeremyhahn/go-keychain/pkg/backend/gcpkms"
	"github.com/jeremyhahn/go-keychain/pkg/storage/file"
)

// initGCPKMSBackend initializes the GCP KMS backend if enabled in configuration
func (s *Server) initGCPKMSBackend() error {
	if s.config.Backends.GCPKMS == nil || !s.config.Backends.GCPKMS.Enabled {
		return nil
	}

	// Create storage for GCP KMS metadata
	storage, err := file.New(s.config.Storage.Path + "/gcpkms")
	if err != nil {
		return fmt.Errorf("failed to create GCP KMS storage: %w", err)
	}

	gcpBackend, err := gcpkms.NewBackend(context.Background(), &gcpkms.Config{
		ProjectID:       s.config.Backends.GCPKMS.ProjectID,
		LocationID:      s.config.Backends.GCPKMS.Location,
		KeyRingID:       s.config.Backends.GCPKMS.KeyRing,
		CredentialsFile: s.config.Backends.GCPKMS.Credentials,
		KeyStorage:      storage,
	})
	if err != nil {
		return fmt.Errorf("failed to create GCP KMS backend: %w", err)
	}

	s.backends["gcpkms"] = gcpBackend
	s.logger.Info("GCP KMS backend initialized", "backend", "gcpkms", "project", s.config.Backends.GCPKMS.ProjectID)
	return nil
}
