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
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// buildGCPKMSPlatformSealer resolves the types.Sealer for the gcpkms
// credential strategy. Like awskms, GCP KMS needs no operator secret this
// phase of startup could fail to resolve: with no CredentialsFile/
// CredentialsJSON set, it authenticates via Application Default Credentials
// (ADC -- environment, workload identity, metadata server), the same ambient
// mode gcpkms.Config already documents. See buildAWSKMSPlatformSealer for
// the metadata-storage and shared-wrapping-key rationale, which applies
// identically here.
func (s *Server) buildGCPKMSPlatformSealer() (types.Sealer, error) {
	if s.config.Backends.GCPKMS == nil {
		return nil, &ErrPlatformStoreStrategyUnavailable{
			Strategy: "gcpkms",
			Reason:   "backends.gcpkms is not configured",
		}
	}

	metadataStorage, err := s.createStorage("platform-store-gcpkms")
	if err != nil {
		return nil, &ErrStorageCreate{Resource: "platform store gcpkms storage", Err: err}
	}

	backend, err := gcpkms.NewBackend(context.Background(), &gcpkms.Config{
		ProjectID:   s.config.Backends.GCPKMS.ProjectID,
		LocationID:  s.config.Backends.GCPKMS.Location,
		KeyRingID:   s.config.Backends.GCPKMS.KeyRing,
		KeyStorage:  metadataStorage,
		CertStorage: metadataStorage,
	})
	if err != nil {
		return nil, err
	}

	keyAttrs := sealKeyAttributesFor(types.StoreGCPKMS)
	if err := s.ensureSealKey(seal.StrategyGCPKMS, backend, keyAttrs); err != nil {
		return nil, err
	}

	return &fixedKeyAttrsSealer{inner: backend, attrs: keyAttrs}, nil
}
