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
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

// TestResolveBarrierCloudSecrets_NilFieldSkipped proves an unconfigured
// (nil) *xkms.SecretValue field -- ambient credentials, the default -- is
// left alone rather than treated as a resolution failure.
func TestResolveBarrierCloudSecrets_NilFieldSkipped(t *testing.T) {
	cfg := &config.BarrierAWSKMSConfig{Region: "us-east-1"}
	err := resolveBarrierCloudSecrets(context.Background(), cfg)
	require.NoError(t, err)
}

// TestResolveBarrierCloudSecrets_UnresolvedReferenceFails proves that an
// explicit credential reference xkey has no resolver for fails closed with
// xkms.ErrUnresolvedSecretURI rather than being read as a literal -- xkey
// registers no resolvers of its own (see resolveBarrierCloudSecrets' doc),
// so this is every explicit reference's outcome until a resolver for a
// scheme xkey can serve is added.
func TestResolveBarrierCloudSecrets_UnresolvedReferenceFails(t *testing.T) {
	cfg := &config.BarrierAWSKMSConfig{
		Region:          "us-east-1",
		SecretAccessKey: &xkms.SecretValue{Raw: "credential://aws-secret-key"},
	}
	err := resolveBarrierCloudSecrets(context.Background(), cfg)
	require.Error(t, err)
	assert.True(t, errors.Is(err, xkms.ErrUnresolvedSecretURI))
}

// TestBuildCloudKMSBarrierStrategy_NotCompiledIn proves that every cloud KMS
// strategy ID reports a typed error naming the missing build tag when this
// binary was built without it -- this test binary carries no awskms/gcpkms/
// azurekv/vault build tag, so cloudKMSStrategyBuilders has no entry for any
// of the four IDs.
func TestBuildCloudKMSBarrierStrategy_NotCompiledIn(t *testing.T) {
	for _, id := range []xkms.StrategyID{xkms.StrategyAWSKMS, xkms.StrategyGCPKMS, xkms.StrategyAzureKV, xkms.StrategyVault} {
		t.Run(string(id), func(t *testing.T) {
			_, _, err := buildCloudKMSBarrierStrategy(context.Background(), id, t.TempDir())
			require.Error(t, err)
			var barrierErr *BarrierError
			require.ErrorAs(t, err, &barrierErr)
			assert.Contains(t, err.Error(), "built without -tags")
		})
	}
}

// TestPersistBarrierCloudKMSConfig_NonCloudStrategyIsNoOp proves that every
// non-cloud-KMS strategy value (including "", auto-detect) never touches
// GetConfig(), so it is safe to call unconditionally from runBarrierInit
// before the config is guaranteed to be loaded.
func TestPersistBarrierCloudKMSConfig_NonCloudStrategyIsNoOp(t *testing.T) {
	saved := loadedConfig
	loadedConfig = nil
	defer func() { loadedConfig = saved }()

	for _, s := range []string{"", "software", "tpm2", "pkcs11"} {
		err := persistBarrierCloudKMSConfig(s)
		require.NoError(t, err, "strategy %q must be a no-op", s)
	}
}

// TestPersistBarrierCloudKMSConfig_NoConfigLoaded proves a cloud KMS
// strategy fails with a typed error, rather than panicking, when GetConfig()
// has not been populated yet.
func TestPersistBarrierCloudKMSConfig_NoConfigLoaded(t *testing.T) {
	saved := loadedConfig
	loadedConfig = nil
	defer func() { loadedConfig = saved }()

	err := persistBarrierCloudKMSConfig("aws_kms")
	require.ErrorIs(t, err, ErrBarrierConfigNotLoaded)
}

// TestPersistBarrierCloudKMSConfig_AWSKMS proves that --strategy aws_kms
// with --aws-region set builds a valid BarrierAWSKMSConfig, saves it into
// the xkey config, and that a later load sees the same settings -- the
// mechanism unseal and headless serve rely on to rebuild the same strategy
// without repeating the flags.
func TestPersistBarrierCloudKMSConfig_AWSKMS(t *testing.T) {
	tmpDir := t.TempDir()
	config.SetConfigDir(tmpDir)
	savedCfg := loadedConfig
	defer func() {
		config.ResetConfigDir()
		loadedConfig = savedCfg
		barrierAWSRegion = ""
		barrierAWSEndpoint = ""
	}()

	loadedConfig = config.DefaultConfig()
	barrierAWSRegion = "us-west-2"
	barrierAWSEndpoint = "https://kms.example.test"

	err := persistBarrierCloudKMSConfig("aws_kms")
	require.NoError(t, err)

	loaded, err := config.LoadFromPath(filepath.Join(tmpDir, "xkey.yaml"))
	require.NoError(t, err)
	require.NotNil(t, loaded.Barrier.CloudKMS.AWSKMS)
	assert.Equal(t, "us-west-2", loaded.Barrier.CloudKMS.AWSKMS.Region)
	assert.Equal(t, "https://kms.example.test", loaded.Barrier.CloudKMS.AWSKMS.Endpoint)
}

// TestPersistBarrierCloudKMSConfig_AWSKMSInvalid proves a missing required
// field (region) is reported as a typed config error rather than silently
// persisted.
func TestPersistBarrierCloudKMSConfig_AWSKMSInvalid(t *testing.T) {
	saved := loadedConfig
	defer func() {
		loadedConfig = saved
		barrierAWSRegion = ""
	}()

	loadedConfig = &config.Config{}
	barrierAWSRegion = ""

	err := persistBarrierCloudKMSConfig("aws_kms")
	require.Error(t, err)
	assert.True(t, errors.Is(err, config.ErrBarrierCloudKMSConfigInvalid))
}
