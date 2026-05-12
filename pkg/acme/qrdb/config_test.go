// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package qrdb

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	t.Run("returns valid defaults", func(t *testing.T) {
		cfg := DefaultConfig()
		require.NotNil(t, cfg)
		assert.Equal(t, ModeStandalone, cfg.Mode)
		assert.Equal(t, ProtocolEmbedded, cfg.Protocol)
		assert.Equal(t, "data/qrdb", cfg.DataDir)
		assert.Equal(t, defaultTimeout, cfg.Timeout)
		require.NotNil(t, cfg.Shutdown)
		assert.Equal(t, defaultGracePeriod, cfg.Shutdown.GracePeriod)
		assert.Equal(t, defaultDrainTimeout, cfg.Shutdown.DrainTimeout)
		assert.True(t, cfg.Shutdown.TransferLeader)
	})

	t.Run("default config validates successfully", func(t *testing.T) {
		cfg := DefaultConfig()
		err := cfg.Validate()
		assert.NoError(t, err)
	})
}

func TestConfigValidate(t *testing.T) {
	t.Run("valid embedded standalone", func(t *testing.T) {
		cfg := &Config{
			Mode:     ModeStandalone,
			Protocol: ProtocolEmbedded,
			DataDir:  "/tmp/data",
		}
		assert.NoError(t, cfg.Validate())
	})

	t.Run("valid grpc remote", func(t *testing.T) {
		cfg := &Config{
			Mode:     ModeStandalone,
			Protocol: ProtocolGRPC,
			Address:  "localhost:9443",
		}
		assert.NoError(t, cfg.Validate())
	})

	t.Run("valid unix socket", func(t *testing.T) {
		cfg := &Config{
			Mode:           ModeStandalone,
			Protocol:       ProtocolUnix,
			UnixSocketPath: "/run/qrdb.sock",
		}
		assert.NoError(t, cfg.Validate())
	})

	t.Run("valid raft mode", func(t *testing.T) {
		cfg := &Config{
			Mode:      ModeRaft,
			Protocol:  ProtocolEmbedded,
			DataDir:   "/tmp/data",
			NodeID:    1,
			ClusterID: 1,
		}
		assert.NoError(t, cfg.Validate())
	})

	t.Run("invalid mode", func(t *testing.T) {
		cfg := &Config{
			Mode:     Mode("invalid"),
			Protocol: ProtocolEmbedded,
			DataDir:  "/tmp/data",
		}
		err := cfg.Validate()
		require.Error(t, err)
		assert.True(t, IsInvalidConfig(err))
	})

	t.Run("invalid protocol", func(t *testing.T) {
		cfg := &Config{
			Mode:     ModeStandalone,
			Protocol: Protocol("invalid"),
		}
		err := cfg.Validate()
		require.Error(t, err)
		assert.True(t, IsInvalidConfig(err))
	})

	t.Run("remote protocol missing address", func(t *testing.T) {
		cfg := &Config{
			Mode:     ModeStandalone,
			Protocol: ProtocolGRPC,
		}
		err := cfg.Validate()
		require.Error(t, err)
		assert.True(t, IsInvalidConfig(err))
	})

	t.Run("unix protocol missing socket path", func(t *testing.T) {
		cfg := &Config{
			Mode:     ModeStandalone,
			Protocol: ProtocolUnix,
		}
		err := cfg.Validate()
		require.Error(t, err)
		assert.True(t, IsInvalidConfig(err))
	})

	t.Run("embedded protocol missing data dir", func(t *testing.T) {
		cfg := &Config{
			Mode:     ModeStandalone,
			Protocol: ProtocolEmbedded,
		}
		err := cfg.Validate()
		require.Error(t, err)
		assert.True(t, IsInvalidConfig(err))
	})

	t.Run("tls cert without key", func(t *testing.T) {
		cfg := &Config{
			Mode:     ModeStandalone,
			Protocol: ProtocolGRPC,
			Address:  "localhost:9443",
			ClientTLS: &TLSClientConfig{
				CertFile: "/path/cert.pem",
			},
		}
		err := cfg.Validate()
		require.Error(t, err)
		assert.True(t, IsInvalidConfig(err))
	})

	t.Run("tls key without cert", func(t *testing.T) {
		cfg := &Config{
			Mode:     ModeStandalone,
			Protocol: ProtocolGRPC,
			Address:  "localhost:9443",
			ClientTLS: &TLSClientConfig{
				KeyFile: "/path/key.pem",
			},
		}
		err := cfg.Validate()
		require.Error(t, err)
		assert.True(t, IsInvalidConfig(err))
	})

	t.Run("raft mode missing node_id", func(t *testing.T) {
		cfg := &Config{
			Mode:      ModeRaft,
			Protocol:  ProtocolEmbedded,
			DataDir:   "/tmp/data",
			ClusterID: 1,
		}
		err := cfg.Validate()
		require.Error(t, err)
		assert.True(t, IsInvalidConfig(err))
	})

	t.Run("raft mode missing cluster_id", func(t *testing.T) {
		cfg := &Config{
			Mode:     ModeRaft,
			Protocol: ProtocolEmbedded,
			DataDir:  "/tmp/data",
			NodeID:   1,
		}
		err := cfg.Validate()
		require.Error(t, err)
		assert.True(t, IsInvalidConfig(err))
	})
}
