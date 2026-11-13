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

//go:build gcpkms

package embeddednode

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend/gcpkms"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

func TestGCPKMSNodeSealConfig_MapsBackendsGCPKMS(t *testing.T) {
	metadata := storage.NewMemory()
	cfg := &config.Config{Backends: config.BackendsConfig{GCPKMS: &config.GCPKMSConfig{
		ProjectID:   "project-a",
		Location:    "us-central1",
		KeyRing:     "node-seal",
		Credentials: "/etc/xkms/gcp.json",
	}}}

	got, err := gcpKMSNodeSealConfig(cfg, metadata)
	require.NoError(t, err)
	require.Equal(t, &gcpkms.Config{
		ProjectID:       "project-a",
		LocationID:      "us-central1",
		KeyRingID:       "node-seal",
		CredentialsFile: "/etc/xkms/gcp.json",
		KeyStorage:      metadata,
		CertStorage:     metadata,
	}, got)
}

func TestBuildGCPKMSNodeSealBackend_RequiresBackendsGCPKMS(t *testing.T) {
	provider, err := buildGCPKMSNodeSealBackend(context.Background(), &config.Config{}, storage.NewMemory(), testLogger())
	var nodeErr *NodeSealError
	require.ErrorAs(t, err, &nodeErr)
	require.Nil(t, provider)
}

// TestBuildGCPKMSNodeSealBackend_RefusesAnInvalidBackendsGCPKMS proves a
// backends.gcpkms section the GCP Cloud KMS backend cannot be built from
// refuses the node seal with the backend's typed error and no provider.
func TestBuildGCPKMSNodeSealBackend_RefusesAnInvalidBackendsGCPKMS(t *testing.T) {
	tests := []struct {
		name   string
		gcpCfg *config.GCPKMSConfig
		want   error
	}{
		{name: "missing project", gcpCfg: &config.GCPKMSConfig{Location: "us-central1", KeyRing: "node-seal"}, want: gcpkms.ErrInvalidProjectID},
		{name: "missing location", gcpCfg: &config.GCPKMSConfig{ProjectID: "project-a", KeyRing: "node-seal"}, want: gcpkms.ErrInvalidLocationID},
		{name: "missing key ring", gcpCfg: &config.GCPKMSConfig{ProjectID: "project-a", Location: "us-central1"}, want: gcpkms.ErrInvalidKeyRingID},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{Backends: config.BackendsConfig{GCPKMS: tt.gcpCfg}}

			provider, err := buildGCPKMSNodeSealBackend(context.Background(), cfg, storage.NewMemory(), testLogger())
			require.ErrorIs(t, err, tt.want)
			require.Nil(t, provider)
		})
	}
}
