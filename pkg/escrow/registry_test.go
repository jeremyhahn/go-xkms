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
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockAgent implements EscrowAgent for testing.
type mockAgent struct {
	agentType    string
	available    bool
	escrowErr    error
	recoverErr   error
	listErr      error
	revokeErr    error
	closeErr     error
	receipts     []*EscrowReceipt
	recoverResp  *RecoverResponse
	records      []EscrowRecord
	escrowCalls  int
	recoverCalls int
}

func newMockAgent(agentType string) *mockAgent {
	return &mockAgent{
		agentType: agentType,
		available: true,
	}
}

func (m *mockAgent) Type() string { return m.agentType }

func (m *mockAgent) Available(_ context.Context) bool { return m.available }

func (m *mockAgent) EscrowKey(_ context.Context, req *EscrowRequest) (*EscrowReceipt, error) {
	m.escrowCalls++
	if m.escrowErr != nil {
		return nil, m.escrowErr
	}
	receipt := &EscrowReceipt{
		EscrowID:   fmt.Sprintf("escrow-%s-%d", m.agentType, m.escrowCalls),
		KeyID:      req.KeyID,
		Agent:      m.agentType,
		EscrowedAt: time.Now().UTC(),
	}
	m.receipts = append(m.receipts, receipt)
	return receipt, nil
}

func (m *mockAgent) RecoverKey(_ context.Context, req *RecoverRequest) (*RecoverResponse, error) {
	m.recoverCalls++
	if m.recoverErr != nil {
		return nil, m.recoverErr
	}
	if m.recoverResp != nil {
		return m.recoverResp, nil
	}
	keyID := req.KeyID
	if keyID == "" {
		keyID = req.EscrowID
	}
	return &RecoverResponse{
		KeyID:             keyID,
		WrappedKey:        []byte("recovered-wrapped-key"),
		WrappingAlgorithm: "AES-KW",
	}, nil
}

func (m *mockAgent) ListEscrowed(_ context.Context) ([]EscrowRecord, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.records, nil
}

func (m *mockAgent) RevokeEscrow(_ context.Context, _ string) error {
	return m.revokeErr
}

func (m *mockAgent) Close() error {
	return m.closeErr
}

func TestNewRegistry(t *testing.T) {
	r := NewRegistry()
	require.NotNil(t, r)
	assert.Empty(t, r.Agents())
}

func TestRegistry_Register_Success(t *testing.T) {
	r := NewRegistry()
	agent := newMockAgent("test")

	err := r.Register("primary", agent)
	require.NoError(t, err)

	got, err := r.Get("primary")
	require.NoError(t, err)
	assert.Equal(t, agent, got)
}

func TestRegistry_Register_EmptyName(t *testing.T) {
	r := NewRegistry()
	err := r.Register("", newMockAgent("test"))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrEmptyAgentName))
}

func TestRegistry_Register_NilAgent(t *testing.T) {
	r := NewRegistry()
	err := r.Register("primary", nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilAgent))
}

func TestRegistry_Register_Duplicate(t *testing.T) {
	r := NewRegistry()
	err := r.Register("primary", newMockAgent("test"))
	require.NoError(t, err)

	err = r.Register("primary", newMockAgent("test2"))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAgentAlreadyRegistered))
}

func TestRegistry_Get_NotFound(t *testing.T) {
	r := NewRegistry()
	_, err := r.Get("nonexistent")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAgentNotConfigured))
}

func TestRegistry_Agents(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register("alpha", newMockAgent("a")))
	require.NoError(t, r.Register("beta", newMockAgent("b")))

	names := r.Agents()
	assert.Len(t, names, 2)
	assert.Contains(t, names, "alpha")
	assert.Contains(t, names, "beta")
}

func TestRegistry_EscrowKeyAll_Success(t *testing.T) {
	r := NewRegistry()
	a1 := newMockAgent("xkms")
	a2 := newMockAgent("kmip")
	require.NoError(t, r.Register("xkms", a1))
	require.NoError(t, r.Register("kmip", a2))

	ctx := context.Background()
	req := &EscrowRequest{
		KeyID:             "key-001",
		WrappedKey:        []byte("wrapped-material"),
		WrappingAlgorithm: "AES-KW",
	}

	receipts, err := r.EscrowKeyAll(ctx, req)
	require.NoError(t, err)
	assert.Len(t, receipts, 2)
	assert.Equal(t, 1, a1.escrowCalls)
	assert.Equal(t, 1, a2.escrowCalls)
}

func TestRegistry_EscrowKeyAll_PartialFailure(t *testing.T) {
	r := NewRegistry()
	a1 := newMockAgent("xkms")
	a2 := newMockAgent("kmip")
	a2.escrowErr = ErrEscrowFailed

	require.NoError(t, r.Register("xkms", a1))
	require.NoError(t, r.Register("kmip", a2))

	ctx := context.Background()
	req := &EscrowRequest{
		KeyID:      "key-001",
		WrappedKey: []byte("wrapped-material"),
	}

	receipts, err := r.EscrowKeyAll(ctx, req)
	require.NoError(t, err)
	assert.Len(t, receipts, 1)
	assert.Equal(t, "xkms", receipts[0].Agent)
}

func TestRegistry_EscrowKeyAll_AllFail(t *testing.T) {
	r := NewRegistry()
	a1 := newMockAgent("xkms")
	a1.escrowErr = ErrAgentUnavailable
	a2 := newMockAgent("kmip")
	a2.escrowErr = ErrEscrowFailed

	require.NoError(t, r.Register("xkms", a1))
	require.NoError(t, r.Register("kmip", a2))

	ctx := context.Background()
	req := &EscrowRequest{
		KeyID:      "key-001",
		WrappedKey: []byte("wrapped-material"),
	}

	_, err := r.EscrowKeyAll(ctx, req)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrEscrowFailed))
}

func TestRegistry_EscrowKeyAll_EmptyRegistry(t *testing.T) {
	r := NewRegistry()
	ctx := context.Background()
	req := &EscrowRequest{
		KeyID:      "key-001",
		WrappedKey: []byte("wrapped-material"),
	}

	_, err := r.EscrowKeyAll(ctx, req)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrRegistryEmpty))
}

func TestRegistry_EscrowKeyAll_NilRequest(t *testing.T) {
	r := NewRegistry()
	_, err := r.EscrowKeyAll(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

func TestRegistry_EscrowKeyAll_InvalidRequest(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register("xkms", newMockAgent("xkms")))

	_, err := r.EscrowKeyAll(context.Background(), &EscrowRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrEmptyKeyID))
}

func TestRegistry_RecoverKeyAny_FirstSucceeds(t *testing.T) {
	r := NewRegistry()
	a1 := newMockAgent("xkms")
	a1.recoverResp = &RecoverResponse{
		KeyID:             "key-001",
		WrappedKey:        []byte("from-xkms"),
		WrappingAlgorithm: "AES-KW",
	}
	a2 := newMockAgent("kmip")

	require.NoError(t, r.Register("xkms", a1))
	require.NoError(t, r.Register("kmip", a2))

	ctx := context.Background()
	req := &RecoverRequest{KeyID: "key-001"}

	resp, err := r.RecoverKeyAny(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, "key-001", resp.KeyID)
	assert.NotNil(t, resp.WrappedKey)
}

func TestRegistry_RecoverKeyAny_FallbackToSecond(t *testing.T) {
	r := NewRegistry()

	// Use a single agent to guarantee behavior (map iteration order is non-deterministic).
	a1 := newMockAgent("xkms")
	a1.recoverErr = ErrKeyNotFound

	// Register only the failing agent and a succeeding one under a predictable setup.
	require.NoError(t, r.Register("failing", a1))

	a2 := newMockAgent("kmip")
	a2.recoverResp = &RecoverResponse{
		KeyID:             "key-001",
		WrappedKey:        []byte("from-kmip"),
		WrappingAlgorithm: "RSA-OAEP-SHA256",
	}
	require.NoError(t, r.Register("succeeding", a2))

	ctx := context.Background()
	req := &RecoverRequest{KeyID: "key-001"}

	resp, err := r.RecoverKeyAny(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, "key-001", resp.KeyID)
}

func TestRegistry_RecoverKeyAny_AllFail(t *testing.T) {
	r := NewRegistry()
	a1 := newMockAgent("xkms")
	a1.recoverErr = ErrKeyNotFound
	a2 := newMockAgent("kmip")
	a2.recoverErr = ErrAgentUnavailable

	require.NoError(t, r.Register("xkms", a1))
	require.NoError(t, r.Register("kmip", a2))

	ctx := context.Background()
	req := &RecoverRequest{KeyID: "key-001"}

	_, err := r.RecoverKeyAny(ctx, req)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrRecoverFailed))
}

func TestRegistry_RecoverKeyAny_EmptyRegistry(t *testing.T) {
	r := NewRegistry()
	_, err := r.RecoverKeyAny(context.Background(), &RecoverRequest{KeyID: "k"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrRegistryEmpty))
}

func TestRegistry_RecoverKeyAny_NilRequest(t *testing.T) {
	r := NewRegistry()
	_, err := r.RecoverKeyAny(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

func TestRegistry_RecoverKeyAny_InvalidRequest(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register("xkms", newMockAgent("xkms")))

	_, err := r.RecoverKeyAny(context.Background(), &RecoverRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrEmptyKeyID))
}

func TestRegistry_ListAll_Aggregates(t *testing.T) {
	r := NewRegistry()

	a1 := newMockAgent("xkms")
	a1.records = []EscrowRecord{
		{EscrowID: "e1", KeyID: "k1", Agent: "xkms"},
		{EscrowID: "e2", KeyID: "k2", Agent: "xkms"},
	}
	a2 := newMockAgent("kmip")
	a2.records = []EscrowRecord{
		{EscrowID: "e3", KeyID: "k3", Agent: "kmip"},
	}

	require.NoError(t, r.Register("xkms", a1))
	require.NoError(t, r.Register("kmip", a2))

	records, err := r.ListAll(context.Background())
	require.NoError(t, err)
	assert.Len(t, records, 3)
}

func TestRegistry_ListAll_PartialFailure(t *testing.T) {
	r := NewRegistry()

	a1 := newMockAgent("xkms")
	a1.records = []EscrowRecord{
		{EscrowID: "e1", KeyID: "k1", Agent: "xkms"},
	}
	a2 := newMockAgent("kmip")
	a2.listErr = ErrAgentUnavailable

	require.NoError(t, r.Register("xkms", a1))
	require.NoError(t, r.Register("kmip", a2))

	records, err := r.ListAll(context.Background())
	require.NoError(t, err)
	assert.Len(t, records, 1)
}

func TestRegistry_ListAll_AllFail(t *testing.T) {
	r := NewRegistry()

	a1 := newMockAgent("xkms")
	a1.listErr = ErrAgentUnavailable

	require.NoError(t, r.Register("xkms", a1))

	_, err := r.ListAll(context.Background())
	require.Error(t, err)
}

func TestRegistry_ListAll_EmptyRegistry(t *testing.T) {
	r := NewRegistry()
	_, err := r.ListAll(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrRegistryEmpty))
}

func TestRegistry_ListAll_EmptyResults(t *testing.T) {
	r := NewRegistry()
	a := newMockAgent("xkms")
	a.records = []EscrowRecord{}
	require.NoError(t, r.Register("xkms", a))

	records, err := r.ListAll(context.Background())
	require.NoError(t, err)
	assert.Empty(t, records)
}

func TestRegistry_Close_Success(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register("a1", newMockAgent("xkms")))
	require.NoError(t, r.Register("a2", newMockAgent("kmip")))

	err := r.Close()
	require.NoError(t, err)
	assert.Empty(t, r.Agents())
}

func TestRegistry_Close_WithErrors(t *testing.T) {
	r := NewRegistry()
	a1 := newMockAgent("xkms")
	a1.closeErr = fmt.Errorf("close failed")
	require.NoError(t, r.Register("xkms", a1))

	err := r.Close()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "close failed")
	// Registry should still be cleared.
	assert.Empty(t, r.Agents())
}

func TestRegistry_Close_EmptyRegistry(t *testing.T) {
	r := NewRegistry()
	err := r.Close()
	require.NoError(t, err)
}
