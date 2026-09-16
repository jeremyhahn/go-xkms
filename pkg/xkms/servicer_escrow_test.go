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

package xkms

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/escrow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeEscrowAgent is an in-memory escrow.EscrowAgent used to exercise the
// XKMSService pass-through servicer without a real KMIP server or remote
// xkms peer. It mirrors the sentinel errors an implementation returns so the
// servicer's ErrNotConfigured / ErrNilRequest guards and error propagation
// can be verified in isolation.
type fakeEscrowAgent struct {
	agentType string
	records   map[string]escrow.EscrowRecord
	escrowErr error
	closed    bool
}

func newFakeEscrowAgent(agentType string) *fakeEscrowAgent {
	return &fakeEscrowAgent{agentType: agentType, records: make(map[string]escrow.EscrowRecord)}
}

func (f *fakeEscrowAgent) Type() string { return f.agentType }

func (f *fakeEscrowAgent) Available(_ context.Context) bool { return !f.closed }

func (f *fakeEscrowAgent) EscrowKey(_ context.Context, req *escrow.EscrowRequest) (*escrow.EscrowReceipt, error) {
	if f.escrowErr != nil {
		return nil, f.escrowErr
	}
	escrowID := "escrow-" + req.KeyID
	f.records[escrowID] = escrow.EscrowRecord{
		EscrowID:          escrowID,
		KeyID:             req.KeyID,
		Agent:             f.agentType,
		WrappingAlgorithm: req.WrappingAlgorithm,
		EscrowedAt:        time.Now().UTC(),
	}
	return &escrow.EscrowReceipt{EscrowID: escrowID, KeyID: req.KeyID, Agent: f.agentType, EscrowedAt: time.Now().UTC()}, nil
}

func (f *fakeEscrowAgent) RecoverKey(_ context.Context, req *escrow.RecoverRequest) (*escrow.RecoverResponse, error) {
	for _, rec := range f.records {
		if rec.EscrowID == req.EscrowID || rec.KeyID == req.KeyID {
			return &escrow.RecoverResponse{KeyID: rec.KeyID, WrappedKey: []byte("wrapped"), WrappingAlgorithm: rec.WrappingAlgorithm}, nil
		}
	}
	return nil, escrow.ErrKeyNotFound
}

func (f *fakeEscrowAgent) ListEscrowed(_ context.Context) ([]escrow.EscrowRecord, error) {
	records := make([]escrow.EscrowRecord, 0, len(f.records))
	for _, rec := range f.records {
		records = append(records, rec)
	}
	return records, nil
}

func (f *fakeEscrowAgent) RevokeEscrow(_ context.Context, escrowID string) error {
	if _, ok := f.records[escrowID]; !ok {
		return escrow.ErrKeyNotFound
	}
	delete(f.records, escrowID)
	return nil
}

func (f *fakeEscrowAgent) Close() error {
	f.closed = true
	return nil
}

func newTestEscrowService(t *testing.T) (*XKMSService, *fakeEscrowAgent) {
	t.Helper()
	registry := escrow.NewRegistry()
	agent := newFakeEscrowAgent("xkms")
	require.NoError(t, registry.Register("primary", agent))

	svc := &XKMSService{}
	svc.SetEscrowRegistry(registry)
	return svc, agent
}

func TestEscrowKey_NotConfigured(t *testing.T) {
	svc := &XKMSService{}
	receipts, err := svc.EscrowKey(context.Background(), &escrow.EscrowRequest{KeyID: "k1", WrappedKey: []byte("wrapped")})
	require.Error(t, err)
	assert.Nil(t, receipts)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestEscrowKey_NilRequest(t *testing.T) {
	svc, _ := newTestEscrowService(t)
	receipts, err := svc.EscrowKey(context.Background(), nil)
	require.Error(t, err)
	assert.Nil(t, receipts)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

func TestEscrowKey_Success(t *testing.T) {
	svc, _ := newTestEscrowService(t)
	receipts, err := svc.EscrowKey(context.Background(), &escrow.EscrowRequest{
		KeyID:             "k1",
		WrappedKey:        []byte("wrapped"),
		WrappingAlgorithm: "AES-KW",
	})
	require.NoError(t, err)
	require.Len(t, receipts, 1)
	assert.Equal(t, "k1", receipts[0].KeyID)
}

func TestRecoverKey_NotConfigured(t *testing.T) {
	svc := &XKMSService{}
	resp, err := svc.RecoverKey(context.Background(), &escrow.RecoverRequest{KeyID: "k1"})
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestRecoverKey_NilRequest(t *testing.T) {
	svc, _ := newTestEscrowService(t)
	resp, err := svc.RecoverKey(context.Background(), nil)
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

func TestRecoverKey_Success(t *testing.T) {
	svc, _ := newTestEscrowService(t)
	_, err := svc.EscrowKey(context.Background(), &escrow.EscrowRequest{
		KeyID:             "k1",
		WrappedKey:        []byte("wrapped"),
		WrappingAlgorithm: "AES-KW",
	})
	require.NoError(t, err)

	resp, err := svc.RecoverKey(context.Background(), &escrow.RecoverRequest{KeyID: "k1"})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "k1", resp.KeyID)
}

func TestListEscrowed_NotConfigured(t *testing.T) {
	svc := &XKMSService{}
	records, err := svc.ListEscrowed(context.Background())
	require.Error(t, err)
	assert.Nil(t, records)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestListEscrowed_Success(t *testing.T) {
	svc, _ := newTestEscrowService(t)
	_, err := svc.EscrowKey(context.Background(), &escrow.EscrowRequest{KeyID: "k1", WrappedKey: []byte("wrapped")})
	require.NoError(t, err)

	records, err := svc.ListEscrowed(context.Background())
	require.NoError(t, err)
	require.Len(t, records, 1)
}

func TestRevokeEscrow_NotConfigured(t *testing.T) {
	svc := &XKMSService{}
	err := svc.RevokeEscrow(context.Background(), "escrow-k1")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestRevokeEscrow_Success(t *testing.T) {
	svc, _ := newTestEscrowService(t)
	_, err := svc.EscrowKey(context.Background(), &escrow.EscrowRequest{KeyID: "k1", WrappedKey: []byte("wrapped")})
	require.NoError(t, err)

	err = svc.RevokeEscrow(context.Background(), "escrow-k1")
	require.NoError(t, err)

	records, err := svc.ListEscrowed(context.Background())
	require.NoError(t, err)
	assert.Empty(t, records)
}
