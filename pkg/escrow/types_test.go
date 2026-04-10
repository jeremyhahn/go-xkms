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

package escrow

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEscrowRequest_Validate_Success(t *testing.T) {
	req := &EscrowRequest{
		KeyID:             "test-key-001",
		WrappedKey:        []byte("wrapped-key-material"),
		WrappingAlgorithm: "AES-KW",
		KeyType:           "aes-256",
		TenantID:          "tenant-1",
		Purpose:           "backup",
		Metadata:          map[string]string{"region": "us-east-1"},
	}
	err := req.Validate()
	require.NoError(t, err)
}

func TestEscrowRequest_Validate_EmptyKeyID(t *testing.T) {
	req := &EscrowRequest{
		KeyID:      "",
		WrappedKey: []byte("wrapped-key-material"),
	}
	err := req.Validate()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrEmptyKeyID))
}

func TestEscrowRequest_Validate_NilWrappedKey(t *testing.T) {
	req := &EscrowRequest{
		KeyID:      "test-key-001",
		WrappedKey: nil,
	}
	err := req.Validate()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilWrappedKey))
}

func TestEscrowRequest_Validate_EmptyWrappedKey(t *testing.T) {
	req := &EscrowRequest{
		KeyID:      "test-key-001",
		WrappedKey: []byte{},
	}
	err := req.Validate()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilWrappedKey))
}

func TestEscrowRequest_Validate_MinimalValid(t *testing.T) {
	req := &EscrowRequest{
		KeyID:      "k",
		WrappedKey: []byte{0x01},
	}
	err := req.Validate()
	require.NoError(t, err)
}

func TestRecoverRequest_Validate_WithEscrowID(t *testing.T) {
	req := &RecoverRequest{
		EscrowID: "escrow-001",
	}
	err := req.Validate()
	require.NoError(t, err)
}

func TestRecoverRequest_Validate_WithKeyID(t *testing.T) {
	req := &RecoverRequest{
		KeyID: "key-001",
	}
	err := req.Validate()
	require.NoError(t, err)
}

func TestRecoverRequest_Validate_WithBothIDs(t *testing.T) {
	req := &RecoverRequest{
		EscrowID: "escrow-001",
		KeyID:    "key-001",
	}
	err := req.Validate()
	require.NoError(t, err)
}

func TestRecoverRequest_Validate_EmptyFields(t *testing.T) {
	req := &RecoverRequest{}
	err := req.Validate()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrEmptyKeyID))
}

func TestAgentConfig_Validate_Success(t *testing.T) {
	cfg := &AgentConfig{
		Type:     AgentTypeXKMS,
		Endpoint: "https://dr-xkms.company.com:8443",
		Name:     "disaster-recovery",
	}
	err := cfg.Validate()
	require.NoError(t, err)
}

func TestAgentConfig_Validate_EmptyType(t *testing.T) {
	cfg := &AgentConfig{
		Type:     "",
		Endpoint: "https://dr-xkms.company.com:8443",
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAgentNotConfigured))
}

func TestAgentConfig_Validate_EmptyEndpoint(t *testing.T) {
	cfg := &AgentConfig{
		Type:     AgentTypeKMIP,
		Endpoint: "",
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrEmptyEndpoint))
}

func TestAgentConfig_Validate_KMIPType(t *testing.T) {
	cfg := &AgentConfig{
		Type:     AgentTypeKMIP,
		Endpoint: "kmip://escrow.company.com:5696",
	}
	err := cfg.Validate()
	require.NoError(t, err)
}

func TestAgentTypeConstants(t *testing.T) {
	assert.Equal(t, "kmip", AgentTypeKMIP)
	assert.Equal(t, "xkms", AgentTypeXKMS)
}
