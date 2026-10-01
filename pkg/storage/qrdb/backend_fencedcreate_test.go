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

package qrdb

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fencedTxClient records the one transaction a fenced create sends and
// answers it as the cluster would.
type fencedTxClient struct {
	*mockKVClient
	req       *transport.TransactionRequest
	succeeded bool
	err       error
}

var _ transport.TransactionClient = (*fencedTxClient)(nil)

func (c *fencedTxClient) ExecuteTransaction(_ context.Context, req *transport.TransactionRequest, _ ...transport.WriteOption) (*transport.TransactionResponse, error) {
	c.req = req
	if c.err != nil {
		return nil, c.err
	}
	return &transport.TransactionResponse{Succeeded: c.succeeded}, nil
}

// The fenced create is ONE transaction: every key's version compared with
// zero, and the put only on success -- evaluated by the cluster, never read
// here first.
func TestBackend_PutIfAllAbsent_IsOneTransactionOverEveryKey(t *testing.T) {
	client := &fencedTxClient{mockKVClient: newMockKVClient(), succeeded: true}
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	created, err := backend.PutIfAllAbsent(context.Background(), "tenants/acme", []byte("record"), "tenants/acme.tombstone")
	require.NoError(t, err)
	assert.True(t, created)

	require.NotNil(t, client.req)
	require.Len(t, client.req.Compares, 2)
	for i, want := range []string{"tenants/acme", "tenants/acme.tombstone"} {
		c := client.req.Compares[i]
		assert.Equal(t, want, string(c.Key))
		assert.Equal(t, transport.CompareVersion, c.Target)
		assert.Equal(t, transport.CompareEqual, c.Result)
		assert.Zero(t, c.Version)
	}
	require.Len(t, client.req.SuccessOps, 1)
	assert.Equal(t, transport.OpPut, client.req.SuccessOps[0].Type)
	assert.Equal(t, "tenants/acme", string(client.req.SuccessOps[0].Key))
	assert.Equal(t, []byte("record"), client.req.SuccessOps[0].Value)
	assert.Empty(t, client.req.FailureOps, "a refused create changes nothing")
}

func TestBackend_PutIfAllAbsent_RefusalIsNotAnError(t *testing.T) {
	client := &fencedTxClient{mockKVClient: newMockKVClient(), succeeded: false}
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	created, err := backend.PutIfAllAbsent(context.Background(), "k", []byte("v"), "fence")
	require.NoError(t, err)
	assert.False(t, created)
}

func TestBackend_PutIfAllAbsent_TransactionFailureIsAnError(t *testing.T) {
	boom := errors.New("raft: not leader")
	client := &fencedTxClient{mockKVClient: newMockKVClient(), err: boom}
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	_, err := backend.PutIfAllAbsent(context.Background(), "k", []byte("v"))
	assert.ErrorIs(t, err, boom)
}

func TestBackend_PutIfAllAbsent_WithoutTransactionsRefuses(t *testing.T) {
	backend := NewBackend(newMockKVClient())
	defer func() { _ = backend.Close() }()

	_, err := backend.PutIfAllAbsent(context.Background(), "k", []byte("v"), "fence")
	assert.ErrorIs(t, err, ErrTransactionsUnsupported, "never a check followed by a write")
}
