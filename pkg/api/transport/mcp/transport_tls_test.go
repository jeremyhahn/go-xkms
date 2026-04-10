// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package mcp

import (
	"crypto/tls"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBuildTLSConfig_PreConfigured exercises the early return path when
// TLSConfig is already provided in the transport configuration.
func TestBuildTLSConfig_PreConfigured(t *testing.T) {
	expected := &tls.Config{MinVersion: tls.VersionTLS13}
	cfg := transport.DefaultConfig()
	cfg.TLSConfig = expected

	tr := &Transport{config: cfg}
	result, err := tr.buildTLSConfig()
	require.NoError(t, err)
	assert.Equal(t, expected, result)
}

// TestBuildTLSConfig_InvalidCAFile exercises the error path when
// the CA certificate file cannot be read.
func TestBuildTLSConfig_InvalidCAFile(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.TLSCAFile = "/nonexistent/path/ca.pem"

	tr := &Transport{config: cfg}
	_, err := tr.buildTLSConfig()
	require.Error(t, err)
	var tlsErr *TLSSetupError
	assert.True(t, errors.As(err, &tlsErr))
	assert.Contains(t, tlsErr.Error(), "failed to read CA certificate")
}

// TestBuildTLSConfig_DefaultPath exercises the default TLS config
// construction path with no CA file, no client cert, no SPKI pin.
func TestBuildTLSConfig_DefaultPath(t *testing.T) {
	cfg := transport.DefaultConfig()
	tr := &Transport{config: cfg}

	result, err := tr.buildTLSConfig()
	require.NoError(t, err)
	assert.Equal(t, uint16(tls.VersionTLS12), result.MinVersion)
}
