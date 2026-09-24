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

//go:build azurekv

package server

import (
	"github.com/jeremyhahn/go-xkms/pkg/backend/azurekv"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// buildAzureKVPlatformSealer resolves the types.Sealer for the azurekv
// credential strategy. Like awskms/gcpkms, Azure Key Vault needs no operator
// secret this phase of startup could fail to resolve: with TenantID/
// ClientID/ClientSecret all left unset, it authenticates via
// DefaultAzureCredential (managed identity, environment, workload identity),
// the same ambient mode azurekv.Config already documents. See
// buildAWSKMSPlatformSealer for the metadata-storage and
// shared-wrapping-key rationale, which applies identically here.
func (s *Server) buildAzureKVPlatformSealer() (types.Sealer, error) {
	if s.config.Backends.AzureKV == nil {
		return nil, &ErrPlatformStoreStrategyUnavailable{
			Strategy: "azurekv",
			Reason:   "backends.azurekv is not configured",
		}
	}

	metadataStorage, err := s.createStorage("platform-store-azurekv")
	if err != nil {
		return nil, &ErrStorageCreate{Resource: "platform store azurekv storage", Err: err}
	}

	backend, err := azurekv.NewBackend(&azurekv.Config{
		VaultURL:           s.config.Backends.AzureKV.VaultURL,
		AllowLocalVaultURL: s.config.Backends.AzureKV.AllowLocalVaultURL,
		KeyStorage:         metadataStorage,
		CertStorage:        metadataStorage,
	})
	if err != nil {
		return nil, err
	}

	keyAttrs := sealKeyAttributesFor(types.StoreAzureKV)
	if err := s.ensureSealKey(seal.StrategyAzureKV, backend, keyAttrs); err != nil {
		return nil, err
	}

	return &fixedKeyAttrsSealer{inner: backend, attrs: keyAttrs}, nil
}
