// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package transport

import (
	"crypto/tls"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	require.NotNil(t, cfg)
	assert.Equal(t, 30*time.Second, cfg.Timeout)
	assert.Equal(t, 3, cfg.MaxRetries)
	assert.Equal(t, 100*time.Millisecond, cfg.RetryBackoff)
	assert.Equal(t, 1, cfg.PoolMinConns)
	assert.Equal(t, 10, cfg.PoolMaxConns)
	assert.NotNil(t, cfg.Headers)
	assert.Empty(t, cfg.Headers)
}

func TestConfig_Clone_NilConfig(t *testing.T) {
	var c *Config
	assert.Nil(t, c.Clone())
}

func TestConfig_Clone_DeepCopy(t *testing.T) {
	cfg := &Config{
		Address:    "localhost:8080",
		TLSEnabled: true,
		Timeout:    5 * time.Second,
		MaxRetries: 2,
		Headers:    map[string]string{"X-Token": "abc"},
		TLSConfig:  &tls.Config{MinVersion: tls.VersionTLS13},
	}

	clone := cfg.Clone()
	require.NotNil(t, clone)

	// Values match
	assert.Equal(t, cfg.Address, clone.Address)
	assert.Equal(t, cfg.TLSEnabled, clone.TLSEnabled)
	assert.Equal(t, cfg.Timeout, clone.Timeout)
	assert.Equal(t, cfg.MaxRetries, clone.MaxRetries)
	assert.Equal(t, cfg.Headers, clone.Headers)

	// Headers are independent copies
	clone.Headers["X-New"] = "val"
	assert.NotContains(t, cfg.Headers, "X-New")

	// TLSConfig is shared (shallow copy by design)
	assert.Same(t, cfg.TLSConfig, clone.TLSConfig)
}

func TestConfig_Clone_NilHeaders(t *testing.T) {
	cfg := &Config{Address: "test"}
	clone := cfg.Clone()
	assert.Nil(t, clone.Headers)
}

func TestConfig_Validate_Nil(t *testing.T) {
	var c *Config
	assert.ErrorIs(t, c.Validate(), ErrInvalidConfig)
}

func TestConfig_Validate_Valid(t *testing.T) {
	cfg := DefaultConfig()
	assert.NoError(t, cfg.Validate())
}

func TestConfig_Validate_NegativeTimeout(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Timeout = -1
	err := cfg.Validate()
	require.Error(t, err)
	var ce *ConfigError
	require.True(t, assert.ErrorAs(t, err, &ce))
	assert.Equal(t, "Timeout", ce.Field)
}

func TestConfig_Validate_NegativeMaxRetries(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxRetries = -1
	err := cfg.Validate()
	require.Error(t, err)
	var ce *ConfigError
	require.True(t, assert.ErrorAs(t, err, &ce))
	assert.Equal(t, "MaxRetries", ce.Field)
}

func TestConfig_Validate_NegativeRetryBackoff(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RetryBackoff = -1
	err := cfg.Validate()
	require.Error(t, err)
	var ce *ConfigError
	require.True(t, assert.ErrorAs(t, err, &ce))
	assert.Equal(t, "RetryBackoff", ce.Field)
}

func TestConfig_Validate_NegativePoolMinConns(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PoolMinConns = -1
	err := cfg.Validate()
	require.Error(t, err)
	var ce *ConfigError
	require.True(t, assert.ErrorAs(t, err, &ce))
	assert.Equal(t, "PoolMinConns", ce.Field)
}

func TestConfig_Validate_NegativePoolMaxConns(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PoolMaxConns = -1
	err := cfg.Validate()
	require.Error(t, err)
	var ce *ConfigError
	require.True(t, assert.ErrorAs(t, err, &ce))
	assert.Equal(t, "PoolMaxConns", ce.Field)
}

func TestConfig_Validate_PoolMinExceedsMax(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PoolMinConns = 20
	cfg.PoolMaxConns = 5
	err := cfg.Validate()
	require.Error(t, err)
	var ce *ConfigError
	require.True(t, assert.ErrorAs(t, err, &ce))
	assert.Equal(t, "PoolMinConns", ce.Field)
}

func TestConfig_Validate_PoolMaxZeroWithMinPositive(t *testing.T) {
	// When PoolMaxConns is 0, the min > max check is skipped
	cfg := DefaultConfig()
	cfg.PoolMinConns = 5
	cfg.PoolMaxConns = 0
	assert.NoError(t, cfg.Validate())
}

func TestWithAddress(t *testing.T) {
	cfg := DefaultConfig()
	err := WithAddress("localhost:8080")(cfg)
	require.NoError(t, err)
	assert.Equal(t, "localhost:8080", cfg.Address)
}

func TestWithAddress_Empty(t *testing.T) {
	cfg := DefaultConfig()
	err := WithAddress("")(cfg)
	require.Error(t, err)
	var ce *ConfigError
	require.True(t, assert.ErrorAs(t, err, &ce))
	assert.Equal(t, "Address", ce.Field)
}

func TestWithTLS(t *testing.T) {
	cfg := DefaultConfig()
	err := WithTLS("/ca.pem")(cfg)
	require.NoError(t, err)
	assert.True(t, cfg.TLSEnabled)
	assert.Equal(t, "/ca.pem", cfg.TLSCAFile)
}

func TestWithTLS_EmptyCA(t *testing.T) {
	cfg := DefaultConfig()
	err := WithTLS("")(cfg)
	require.NoError(t, err)
	assert.True(t, cfg.TLSEnabled)
	assert.Empty(t, cfg.TLSCAFile)
}

func TestWithMTLS(t *testing.T) {
	cfg := DefaultConfig()
	err := WithMTLS("/cert.pem", "/key.pem", "/ca.pem")(cfg)
	require.NoError(t, err)
	assert.True(t, cfg.TLSEnabled)
	assert.Equal(t, "/cert.pem", cfg.TLSCertFile)
	assert.Equal(t, "/key.pem", cfg.TLSKeyFile)
	assert.Equal(t, "/ca.pem", cfg.TLSCAFile)
}

func TestWithMTLS_EmptyCert(t *testing.T) {
	cfg := DefaultConfig()
	err := WithMTLS("", "/key.pem", "/ca.pem")(cfg)
	require.Error(t, err)
	var ce *ConfigError
	require.True(t, assert.ErrorAs(t, err, &ce))
	assert.Equal(t, "TLSCertFile", ce.Field)
}

func TestWithMTLS_EmptyKey(t *testing.T) {
	cfg := DefaultConfig()
	err := WithMTLS("/cert.pem", "", "/ca.pem")(cfg)
	require.Error(t, err)
	var ce *ConfigError
	require.True(t, assert.ErrorAs(t, err, &ce))
	assert.Equal(t, "TLSKeyFile", ce.Field)
}

func TestWithTLSConfig(t *testing.T) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
	cfg := DefaultConfig()
	err := WithTLSConfig(tlsCfg)(cfg)
	require.NoError(t, err)
	assert.True(t, cfg.TLSEnabled)
	assert.Same(t, tlsCfg, cfg.TLSConfig)
}

func TestWithTLSConfig_Nil(t *testing.T) {
	cfg := DefaultConfig()
	err := WithTLSConfig(nil)(cfg)
	require.Error(t, err)
	var ce *ConfigError
	require.True(t, assert.ErrorAs(t, err, &ce))
	assert.Equal(t, "TLSConfig", ce.Field)
}

func TestWithSPKIPin(t *testing.T) {
	cfg := DefaultConfig()
	err := WithSPKIPin("abcdef1234")(cfg)
	require.NoError(t, err)
	assert.Equal(t, "abcdef1234", cfg.SPKIPin)
	assert.True(t, cfg.TLSEnabled)
}

func TestWithSPKIPin_Empty(t *testing.T) {
	cfg := DefaultConfig()
	err := WithSPKIPin("")(cfg)
	require.Error(t, err)
	var ce *ConfigError
	require.True(t, assert.ErrorAs(t, err, &ce))
	assert.Equal(t, "SPKIPin", ce.Field)
}

func TestWithTimeout(t *testing.T) {
	cfg := DefaultConfig()
	err := WithTimeout(10 * time.Second)(cfg)
	require.NoError(t, err)
	assert.Equal(t, 10*time.Second, cfg.Timeout)
}

func TestWithTimeout_Zero(t *testing.T) {
	cfg := DefaultConfig()
	err := WithTimeout(0)(cfg)
	require.NoError(t, err)
	assert.Equal(t, time.Duration(0), cfg.Timeout)
}

func TestWithTimeout_Negative(t *testing.T) {
	cfg := DefaultConfig()
	err := WithTimeout(-1)(cfg)
	require.Error(t, err)
	var ce *ConfigError
	require.True(t, assert.ErrorAs(t, err, &ce))
	assert.Equal(t, "Timeout", ce.Field)
}

func TestWithRetry(t *testing.T) {
	cfg := DefaultConfig()
	err := WithRetry(5, 200*time.Millisecond)(cfg)
	require.NoError(t, err)
	assert.Equal(t, 5, cfg.MaxRetries)
	assert.Equal(t, 200*time.Millisecond, cfg.RetryBackoff)
}

func TestWithRetry_NegativeRetries(t *testing.T) {
	cfg := DefaultConfig()
	err := WithRetry(-1, 100*time.Millisecond)(cfg)
	require.Error(t, err)
	var ce *ConfigError
	require.True(t, assert.ErrorAs(t, err, &ce))
	assert.Equal(t, "MaxRetries", ce.Field)
}

func TestWithRetry_NegativeBackoff(t *testing.T) {
	cfg := DefaultConfig()
	err := WithRetry(3, -1)(cfg)
	require.Error(t, err)
	var ce *ConfigError
	require.True(t, assert.ErrorAs(t, err, &ce))
	assert.Equal(t, "RetryBackoff", ce.Field)
}

func TestWithConnectionPool(t *testing.T) {
	cfg := DefaultConfig()
	err := WithConnectionPool(2, 20)(cfg)
	require.NoError(t, err)
	assert.Equal(t, 2, cfg.PoolMinConns)
	assert.Equal(t, 20, cfg.PoolMaxConns)
}

func TestWithConnectionPool_NegativeMin(t *testing.T) {
	cfg := DefaultConfig()
	err := WithConnectionPool(-1, 10)(cfg)
	require.Error(t, err)
}

func TestWithConnectionPool_NegativeMax(t *testing.T) {
	cfg := DefaultConfig()
	err := WithConnectionPool(1, -1)(cfg)
	require.Error(t, err)
}

func TestWithConnectionPool_MinExceedsMax(t *testing.T) {
	cfg := DefaultConfig()
	err := WithConnectionPool(20, 5)(cfg)
	require.Error(t, err)
}

func TestWithConnectionPool_MaxZero(t *testing.T) {
	cfg := DefaultConfig()
	err := WithConnectionPool(5, 0)(cfg)
	require.NoError(t, err)
}

func TestWithHeaders(t *testing.T) {
	cfg := DefaultConfig()
	err := WithHeaders(map[string]string{"X-A": "1", "X-B": "2"})(cfg)
	require.NoError(t, err)
	assert.Equal(t, "1", cfg.Headers["X-A"])
	assert.Equal(t, "2", cfg.Headers["X-B"])
}

func TestWithHeaders_NilMap(t *testing.T) {
	cfg := &Config{} // Headers is nil
	err := WithHeaders(map[string]string{"X-A": "1"})(cfg)
	require.NoError(t, err)
	assert.Equal(t, "1", cfg.Headers["X-A"])
}

func TestWithHeader(t *testing.T) {
	cfg := DefaultConfig()
	err := WithHeader("Authorization", "Bearer token")(cfg)
	require.NoError(t, err)
	assert.Equal(t, "Bearer token", cfg.Headers["Authorization"])
}

func TestWithHeader_EmptyKey(t *testing.T) {
	cfg := DefaultConfig()
	err := WithHeader("", "value")(cfg)
	require.Error(t, err)
	var ce *ConfigError
	require.True(t, assert.ErrorAs(t, err, &ce))
	assert.Equal(t, "Header", ce.Field)
}

func TestWithHeader_NilHeaders(t *testing.T) {
	cfg := &Config{} // Headers is nil
	err := WithHeader("X-Test", "val")(cfg)
	require.NoError(t, err)
	assert.Equal(t, "val", cfg.Headers["X-Test"])
}

func TestWithJWTToken(t *testing.T) {
	cfg := DefaultConfig()
	err := WithJWTToken("my.jwt.token")(cfg)
	require.NoError(t, err)
	assert.Equal(t, "my.jwt.token", cfg.JWTToken)
}

func TestWithJWTToken_Empty(t *testing.T) {
	cfg := DefaultConfig()
	err := WithJWTToken("")(cfg)
	require.NoError(t, err)
	assert.Empty(t, cfg.JWTToken)
}

func TestApplyOptions_Success(t *testing.T) {
	cfg := DefaultConfig()
	err := ApplyOptions(cfg,
		WithAddress("localhost:8080"),
		WithTimeout(5*time.Second),
		WithHeader("X-Custom", "val"),
	)
	require.NoError(t, err)
	assert.Equal(t, "localhost:8080", cfg.Address)
	assert.Equal(t, 5*time.Second, cfg.Timeout)
	assert.Equal(t, "val", cfg.Headers["X-Custom"])
}

func TestApplyOptions_ErrorStopsProcessing(t *testing.T) {
	cfg := DefaultConfig()
	err := ApplyOptions(cfg,
		WithAddress(""), // This will fail
		WithTimeout(5*time.Second),
	)
	require.Error(t, err)
	// Timeout should not have been applied
	assert.Equal(t, 30*time.Second, cfg.Timeout)
}

func TestApplyOptions_NoOptions(t *testing.T) {
	cfg := DefaultConfig()
	err := ApplyOptions(cfg)
	require.NoError(t, err)
}
