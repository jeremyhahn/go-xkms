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

func TestWithConfig(t *testing.T) {
	t.Run("sets config", func(t *testing.T) {
		cfg := &Config{Mode: ModeRaft, Protocol: ProtocolGRPC}
		sc := &serviceConfig{}
		WithConfig(cfg)(sc)
		require.NotNil(t, sc.config)
		assert.Equal(t, ModeRaft, sc.config.Mode)
		assert.Equal(t, ProtocolGRPC, sc.config.Protocol)
	})

	t.Run("nil config", func(t *testing.T) {
		sc := &serviceConfig{config: DefaultConfig()}
		WithConfig(nil)(sc)
		assert.Nil(t, sc.config)
	})
}

func TestWithQRDBClient(t *testing.T) {
	t.Run("sets client", func(t *testing.T) {
		// We cannot create a real sdk.Client without a transport,
		// so we verify the option sets nil and does not panic.
		sc := &serviceConfig{}
		WithQRDBClient(nil)(sc)
		assert.Nil(t, sc.client)
	})

	t.Run("does not affect other fields", func(t *testing.T) {
		cfg := DefaultConfig()
		sc := &serviceConfig{config: cfg}
		WithQRDBClient(nil)(sc)
		assert.Equal(t, cfg, sc.config)
	})
}

func TestWithKVStore(t *testing.T) {
	t.Run("sets kvstore", func(t *testing.T) {
		memKV := NewMemoryKVClient()
		adapter := NewKVStoreAdapter(memKV)
		sc := &serviceConfig{}
		WithKVStore(adapter)(sc)
		require.NotNil(t, sc.kvStore)
	})

	t.Run("nil kvstore", func(t *testing.T) {
		sc := &serviceConfig{}
		WithKVStore(nil)(sc)
		assert.Nil(t, sc.kvStore)
	})
}
