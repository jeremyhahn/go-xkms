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
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTestServiceMethodAccess(t *testing.T) {
	t.Run("returns valid service with all accessors", func(t *testing.T) {
		svc := NewTestService()
		require.NotNil(t, svc)

		// KV should be non-nil.
		assert.NotNil(t, svc.KV())

		// Admin should be non-nil.
		assert.NotNil(t, svc.Admin())

		// Config should return default config.
		cfg := svc.Config()
		require.NotNil(t, cfg)
		assert.Equal(t, ModeStandalone, cfg.Mode)
		assert.Equal(t, ProtocolEmbedded, cfg.Protocol)

		// Healthy should return true for new service.
		assert.True(t, svc.Healthy(context.Background()))
	})

	t.Run("close makes service unhealthy", func(t *testing.T) {
		svc := NewTestService()
		require.NotNil(t, svc)

		assert.True(t, svc.Healthy(context.Background()))
		err := svc.Close()
		assert.NoError(t, err)
		assert.False(t, svc.Healthy(context.Background()))
	})
}

func TestServiceInterfaceCompliance(t *testing.T) {
	t.Run("testService implements Service", func(t *testing.T) {
		var _ = NewTestService()
	})

	t.Run("KV operations work through interface", func(t *testing.T) {
		svc := NewTestService()
		ctx := context.Background()

		err := svc.KV().Put(ctx, "test-key", []byte("test-value"))
		require.NoError(t, err)

		val, err := svc.KV().Get(ctx, "test-key")
		require.NoError(t, err)
		assert.Equal(t, []byte("test-value"), val)
	})
}
