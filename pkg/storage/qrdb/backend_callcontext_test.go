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

package qrdb

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type boundKey struct{}

// bindMarker is a CallContext that marks the context it derives.
func bindMarker(ctx context.Context) (context.Context, error) {
	return context.WithValue(ctx, boundKey{}, true), nil
}

var errBind = errors.New("no service principal")

func failingBind(context.Context) (context.Context, error) { return nil, errBind }

// ctxRecordingClient is a mockKVClient that records whether each call ran on
// a context bindMarker derived.
type ctxRecordingClient struct {
	*mockKVClient
	unbound []string
}

func (c *ctxRecordingClient) record(ctx context.Context, op string) {
	if ctx.Value(boundKey{}) == nil {
		c.unbound = append(c.unbound, op)
	}
}

func (c *ctxRecordingClient) Put(ctx context.Context, key string, value []byte, opts ...transport.WriteOption) error {
	c.record(ctx, "put")
	return c.mockKVClient.Put(ctx, key, value, opts...)
}

func (c *ctxRecordingClient) Get(ctx context.Context, key string, opts ...transport.ReadOption) ([]byte, error) {
	c.record(ctx, "get")
	return c.mockKVClient.Get(ctx, key, opts...)
}

func (c *ctxRecordingClient) Delete(ctx context.Context, key string, opts ...transport.WriteOption) error {
	c.record(ctx, "delete")
	return c.mockKVClient.Delete(ctx, key, opts...)
}

func (c *ctxRecordingClient) List(ctx context.Context, prefix string, opts ...transport.ReadOption) ([]string, error) {
	c.record(ctx, "list")
	return c.mockKVClient.List(ctx, prefix, opts...)
}

func (c *ctxRecordingClient) Scan(ctx context.Context, prefix string, opts ...transport.ReadOption) (map[string][]byte, error) {
	c.record(ctx, "scan")
	return c.mockKVClient.Scan(ctx, prefix, opts...)
}

func (c *ctxRecordingClient) Exists(ctx context.Context, key string, opts ...transport.ReadOption) (bool, error) {
	c.record(ctx, "exists")
	return c.mockKVClient.Exists(ctx, key, opts...)
}

// TestWithCallContext_EveryCallRunsBound proves every call the backend makes
// into its client runs on the context WithCallContext derives.
func TestWithCallContext_EveryCallRunsBound(t *testing.T) {
	ctx := context.Background()
	client := &ctxRecordingClient{mockKVClient: newMockKVClient()}
	backend := NewBackend(client, WithCallContext(bindMarker))

	require.NoError(t, backend.Put(ctx, "k", []byte("v")))
	_, err := backend.Get(ctx, "k")
	require.NoError(t, err)
	_, err = backend.Exists(ctx, "k")
	require.NoError(t, err)
	_, err = backend.List(ctx, "")
	require.NoError(t, err)
	require.NoError(t, backend.Scan(ctx, "", func(string, []byte) error { return nil }))
	require.NoError(t, backend.Delete(ctx, "k"))

	assert.Empty(t, client.unbound, "calls that ran on the caller's context")
}

// TestWithCallContext_Unset proves a backend without WithCallContext runs on
// the caller's context unchanged.
func TestWithCallContext_Unset(t *testing.T) {
	client := &ctxRecordingClient{mockKVClient: newMockKVClient()}
	backend := NewBackend(client)

	require.NoError(t, backend.Put(context.Background(), "k", []byte("v")))
	assert.Equal(t, []string{"put"}, client.unbound)
}

// TestWithCallContext_BindErrorFailsEveryCall proves a bind failure fails
// each operation with a typed BackendError before it reaches the client.
func TestWithCallContext_BindErrorFailsEveryCall(t *testing.T) {
	ctx := context.Background()
	client := newMockKVClient()
	client.store["k"] = []byte("v")
	backend := NewBackend(client, WithCallContext(failingBind))

	calls := map[string]func() error{
		"get":    func() error { _, err := backend.Get(ctx, "k"); return err },
		"put":    func() error { return backend.Put(ctx, "k", []byte("w")) },
		"delete": func() error { return backend.Delete(ctx, "k") },
		"list":   func() error { _, err := backend.List(ctx, ""); return err },
		"scan":   func() error { return backend.Scan(ctx, "", func(string, []byte) error { return nil }) },
		"exists": func() error { _, err := backend.Exists(ctx, "k"); return err },
		"put-if-absent": func() error {
			_, err := backend.PutIfAbsent(ctx, "n", []byte("w"))
			return err
		},
		"put-if-all-absent": func() error {
			_, err := backend.PutIfAllAbsent(ctx, "n", []byte("w"), "f")
			return err
		},
		"compare-and-swap": func() error {
			_, _, err := backend.CompareAndSwap(ctx, "k", []byte("v"), []byte("w"))
			return err
		},
		"compare-and-delete": func() error {
			_, err := backend.CompareAndDelete(ctx, "k", []byte("v"))
			return err
		},
	}
	for op, call := range calls {
		t.Run(op, func(t *testing.T) {
			err := call()
			var backendErr *BackendError
			require.ErrorAs(t, err, &backendErr)
			assert.Equal(t, op, backendErr.Op)
			assert.ErrorIs(t, err, errBind)
		})
	}
	assert.Equal(t, []byte("v"), client.store["k"], "no call reached the client")
	assert.NotContains(t, client.store, "n")
}
