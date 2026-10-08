// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package embeddednode

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend/azurekv"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

func TestAzureKVNodeSealConfig_MapsBackendsAzureKV(t *testing.T) {
	metadata := storage.NewMemory()
	cfg := &config.Config{Backends: config.BackendsConfig{AzureKV: &config.AzureKVConfig{
		VaultURL:           "http://localhost:8443",
		ClientID:           "ignored-by-the-node-seal",
		AllowLocalVaultURL: true,
	}}}

	got, err := azureKVNodeSealConfig(cfg, metadata, testLogger())
	require.NoError(t, err)
	require.Equal(t, &azurekv.Config{
		VaultURL:           "http://localhost:8443",
		AllowLocalVaultURL: true,
		KeyStorage:         metadata,
		CertStorage:        metadata,
	}, got)
}

func TestBuildAzureKVNodeSealBackend_RequiresBackendsAzureKV(t *testing.T) {
	provider, err := buildAzureKVNodeSealBackend(context.Background(), &config.Config{}, storage.NewMemory(), testLogger())
	var nodeErr *NodeSealError
	require.ErrorAs(t, err, &nodeErr)
	require.Nil(t, provider)
}
