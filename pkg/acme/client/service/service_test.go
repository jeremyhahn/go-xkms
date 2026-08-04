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

package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewService verifies the constructor returns a fully initialized Service.
func TestNewService(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Accounts["test-ca"] = validAccountConfig()

	svc, err := NewService(cfg, testLogger())
	require.NoError(t, err)
	require.NotNil(t, svc)

	assert.NotNil(t, svc.Accounts())
	assert.NotNil(t, svc.Certificates())
	assert.NotNil(t, svc.Deployer())
	assert.NotNil(t, svc.Config())
	assert.Equal(t, cfg, svc.Config())
}

// TestNewService_DefaultConfig verifies NewService works with default config.
func TestNewService_DefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	svc, err := NewService(cfg, testLogger())
	require.NoError(t, err)
	require.NotNil(t, svc)
}

// TestService_Accounts verifies the Accounts accessor returns the account manager.
func TestService_Accounts(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Accounts["test-ca"] = validAccountConfig()

	svc, err := NewService(cfg, testLogger())
	require.NoError(t, err)

	am := svc.Accounts()
	require.NotNil(t, am)

	acct, err := am.Get("test-ca")
	require.NoError(t, err)
	assert.Equal(t, "admin@example.com", acct.Email)
}

// TestService_Certificates verifies the Certificates accessor.
func TestService_Certificates(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Accounts["test-ca"] = validAccountConfig()
	cfg.Certificates["web"] = &CertificateSpec{
		Account: "test-ca",
		Subject: SubjectConfig{CN: "example.com"},
		Key: &KeyConfig{
			Algorithm: "ECDSA",
			Store:     "software",
			ECC:       &ECCConfig{Curve: "P-256"},
		},
		Challenge: "http-01",
	}

	svc, err := NewService(cfg, testLogger())
	require.NoError(t, err)

	certs := svc.Certificates().List("")
	assert.Len(t, certs, 1)
	assert.Contains(t, certs, "web")
}

// TestService_StartStopRenewal verifies the renewal lifecycle methods.
func TestService_StartStopRenewal(t *testing.T) {
	cfg := DefaultConfig()
	svc, err := NewService(cfg, testLogger())
	require.NoError(t, err)

	ctx := context.Background()

	err = svc.StartRenewal(ctx)
	require.NoError(t, err)

	err = svc.StopRenewal()
	require.NoError(t, err)
}

// TestService_StartRenewalTwice verifies that starting renewal twice fails.
func TestService_StartRenewalTwice(t *testing.T) {
	cfg := DefaultConfig()
	svc, err := NewService(cfg, testLogger())
	require.NoError(t, err)

	ctx := context.Background()

	err = svc.StartRenewal(ctx)
	require.NoError(t, err)
	defer func() { _ = svc.StopRenewal() }()

	err = svc.StartRenewal(ctx)
	require.Error(t, err)
}

// TestDefaultConfig verifies that DefaultConfig returns sensible defaults.
func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	require.NotNil(t, config)

	// Storage defaults
	assert.Equal(t, "filesystem", config.Storage.Backend)
	assert.Equal(t, "/var/lib/trusted-acme/client-storage", config.Storage.Options["path"])

	// XKMS defaults
	assert.Equal(t, "software", config.XKMS.Backend)
	assert.Equal(t, "/var/lib/trusted-acme/client-keys", config.XKMS.Options["path"])

	// Logging defaults
	assert.Equal(t, "info", config.Logging.Level)
	assert.Equal(t, "json", config.Logging.Format)
	assert.Equal(t, "stdout", config.Logging.Output)

	// Challenge defaults
	assert.Equal(t, "80", config.Challenge.HTTP01.Port)
	assert.Equal(t, 300, config.Challenge.DNS01.TTL)

	// Maps initialized
	assert.NotNil(t, config.Accounts)
	assert.NotNil(t, config.Certificates)
	assert.Empty(t, config.Accounts)
	assert.Empty(t, config.Certificates)
}
