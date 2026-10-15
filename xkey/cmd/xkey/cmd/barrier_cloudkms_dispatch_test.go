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

package cmd

import (
	"context"
	"io"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withCloudKMSBuilder registers fn as the builder for id for the duration
// of the test, restoring whatever a provider tag registered.
func withCloudKMSBuilder(t *testing.T, id xkms.StrategyID, fn cloudKMSStrategyBuilder) {
	t.Helper()
	previous, had := cloudKMSStrategyBuilders[id]
	registerCloudKMSStrategyBuilder(id, fn)
	t.Cleanup(func() {
		if had {
			cloudKMSStrategyBuilders[id] = previous
			return
		}
		delete(cloudKMSStrategyBuilders, id)
	})
}

// withoutCloudKMSBuilder hides the builder a provider tag registered for id
// for the duration of the test, so "not compiled in" paths are tested the
// same way under every tag set.
func withoutCloudKMSBuilder(t *testing.T, id xkms.StrategyID) {
	t.Helper()
	if fn, ok := cloudKMSStrategyBuilders[id]; ok {
		delete(cloudKMSStrategyBuilders, id)
		t.Cleanup(func() { cloudKMSStrategyBuilders[id] = fn })
	}
}

// TestBuildCloudKMSBarrierStrategy_NoConfigLoaded proves a compiled-in
// provider is never reached without a loaded config: every builder reads
// its section from GetConfig(), and a nil config used to panic the AWS one.
func TestBuildCloudKMSBarrierStrategy_NoConfigLoaded(t *testing.T) {
	saved := loadedConfig
	loadedConfig = nil
	t.Cleanup(func() { loadedConfig = saved })

	for _, id := range []xkms.StrategyID{xkms.StrategyAWSKMS, xkms.StrategyGCPKMS, xkms.StrategyAzureKV, xkms.StrategyVault} {
		t.Run(string(id), func(t *testing.T) {
			withCloudKMSBuilder(t, id, func(context.Context, string) (xkms.SealingStrategy, io.Closer, error) {
				t.Fatal("builder called without a loaded config")
				return nil, nil, nil
			})

			strategy, closer, err := buildCloudKMSBarrierStrategy(context.Background(), id, t.TempDir())
			require.ErrorIs(t, err, ErrBarrierConfigNotLoaded)
			assert.Nil(t, strategy)
			assert.Nil(t, closer)
		})
	}
}

// TestBuildCloudKMSBarrierStrategy_DispatchesToRegisteredBuilder proves the
// dispatch hands the data directory to the builder and returns its result.
func TestBuildCloudKMSBarrierStrategy_DispatchesToRegisteredBuilder(t *testing.T) {
	saved := loadedConfig
	loadedConfig = config.DefaultConfig()
	t.Cleanup(func() { loadedConfig = saved })

	dataDir := t.TempDir()
	var gotDir string
	withCloudKMSBuilder(t, xkms.StrategyVault, func(_ context.Context, dir string) (xkms.SealingStrategy, io.Closer, error) {
		gotDir = dir
		return nil, nil, ErrBarrierCreateFailed
	})

	_, _, err := buildCloudKMSBarrierStrategy(context.Background(), xkms.StrategyVault, dataDir)
	require.ErrorIs(t, err, ErrBarrierCreateFailed)
	assert.Equal(t, dataDir, gotDir)
}
