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

package kmip

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/escrow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewKMIPAgent_Success(t *testing.T) {
	agent, err := NewKMIPAgent(&KMIPConfig{
		Endpoint: "kmip://escrow.company.com:5696",
	})
	require.NoError(t, err)
	require.NotNil(t, agent)
	assert.Equal(t, "kmip://escrow.company.com:5696", agent.config.Endpoint)
}

func TestNewKMIPAgent_NilConfig(t *testing.T) {
	_, err := NewKMIPAgent(nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrAgentNotConfigured))
}

func TestNewKMIPAgent_EmptyEndpoint(t *testing.T) {
	_, err := NewKMIPAgent(&KMIPConfig{
		Endpoint: "",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrEmptyEndpoint))
}

func TestKMIPAgent_Type(t *testing.T) {
	agent, err := NewKMIPAgent(&KMIPConfig{
		Endpoint: "kmip://escrow.company.com:5696",
	})
	require.NoError(t, err)
	assert.Equal(t, escrow.AgentTypeKMIP, agent.Type())
}

func TestKMIPAgent_Available(t *testing.T) {
	agent, err := NewKMIPAgent(&KMIPConfig{
		Endpoint: "kmip://escrow.company.com:5696",
	})
	require.NoError(t, err)
	assert.False(t, agent.Available(context.Background()))
}

func TestKMIPAgent_EscrowKey_NotImplemented(t *testing.T) {
	agent, err := NewKMIPAgent(&KMIPConfig{
		Endpoint: "kmip://escrow.company.com:5696",
	})
	require.NoError(t, err)

	_, err = agent.EscrowKey(context.Background(), &escrow.EscrowRequest{
		KeyID:             "key-001",
		WrappedKey:        []byte("wrapped-key-material"),
		WrappingAlgorithm: "AES-KW",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrNotImplemented))
}

func TestKMIPAgent_EscrowKey_NilRequest(t *testing.T) {
	agent, err := NewKMIPAgent(&KMIPConfig{
		Endpoint: "kmip://escrow.company.com:5696",
	})
	require.NoError(t, err)

	_, err = agent.EscrowKey(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrNilRequest))
}

func TestKMIPAgent_EscrowKey_InvalidRequest(t *testing.T) {
	agent, err := NewKMIPAgent(&KMIPConfig{
		Endpoint: "kmip://escrow.company.com:5696",
	})
	require.NoError(t, err)

	_, err = agent.EscrowKey(context.Background(), &escrow.EscrowRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrEmptyKeyID))
}

func TestKMIPAgent_RecoverKey_NotImplemented(t *testing.T) {
	agent, err := NewKMIPAgent(&KMIPConfig{
		Endpoint: "kmip://escrow.company.com:5696",
	})
	require.NoError(t, err)

	_, err = agent.RecoverKey(context.Background(), &escrow.RecoverRequest{
		KeyID: "key-001",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrNotImplemented))
}

func TestKMIPAgent_RecoverKey_NilRequest(t *testing.T) {
	agent, err := NewKMIPAgent(&KMIPConfig{
		Endpoint: "kmip://escrow.company.com:5696",
	})
	require.NoError(t, err)

	_, err = agent.RecoverKey(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrNilRequest))
}

func TestKMIPAgent_RecoverKey_InvalidRequest(t *testing.T) {
	agent, err := NewKMIPAgent(&KMIPConfig{
		Endpoint: "kmip://escrow.company.com:5696",
	})
	require.NoError(t, err)

	_, err = agent.RecoverKey(context.Background(), &escrow.RecoverRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrEmptyKeyID))
}

func TestKMIPAgent_ListEscrowed_NotImplemented(t *testing.T) {
	agent, err := NewKMIPAgent(&KMIPConfig{
		Endpoint: "kmip://escrow.company.com:5696",
	})
	require.NoError(t, err)

	_, err = agent.ListEscrowed(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrNotImplemented))
}

func TestKMIPAgent_RevokeEscrow_NotImplemented(t *testing.T) {
	agent, err := NewKMIPAgent(&KMIPConfig{
		Endpoint: "kmip://escrow.company.com:5696",
	})
	require.NoError(t, err)

	err = agent.RevokeEscrow(context.Background(), "escrow-001")
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrNotImplemented))
}

func TestKMIPAgent_RevokeEscrow_EmptyID(t *testing.T) {
	agent, err := NewKMIPAgent(&KMIPConfig{
		Endpoint: "kmip://escrow.company.com:5696",
	})
	require.NoError(t, err)

	err = agent.RevokeEscrow(context.Background(), "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrEmptyKeyID))
}

func TestKMIPAgent_Close(t *testing.T) {
	agent, err := NewKMIPAgent(&KMIPConfig{
		Endpoint: "kmip://escrow.company.com:5696",
	})
	require.NoError(t, err)

	err = agent.Close()
	require.NoError(t, err)
}

func TestKMIPConfig_Validate_Success(t *testing.T) {
	cfg := &KMIPConfig{
		Endpoint: "kmip://escrow.company.com:5696",
	}
	err := cfg.Validate()
	require.NoError(t, err)
}

func TestKMIPConfig_Validate_EmptyEndpoint(t *testing.T) {
	cfg := &KMIPConfig{}
	err := cfg.Validate()
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrEmptyEndpoint))
}
