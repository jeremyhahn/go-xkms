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

package serverregistry

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServerEntry_Validate_Success(t *testing.T) {
	entry := &ServerEntry{
		URL:           "https://xkms.example.com:8443",
		Name:          "Production XKMS",
		CAFingerprint: "SHA256:abc123",
		Protocol:      ProtocolREST,
	}
	err := entry.Validate()
	require.NoError(t, err)
}

func TestServerEntry_Validate_EmptyURL(t *testing.T) {
	entry := &ServerEntry{
		URL:  "",
		Name: "No URL Server",
	}
	err := entry.Validate()
	require.ErrorIs(t, err, ErrInvalidURL)
}

func TestServerEntry_Validate_MinimalEntry(t *testing.T) {
	entry := &ServerEntry{
		URL: "https://xkms.example.com",
	}
	err := entry.Validate()
	require.NoError(t, err)
}

func TestProtocolConstants(t *testing.T) {
	assert.Equal(t, "rest", ProtocolREST)
	assert.Equal(t, "grpc", ProtocolGRPC)
	assert.Equal(t, "quic", ProtocolQUIC)
	assert.Equal(t, "mcp", ProtocolMCP)
}
