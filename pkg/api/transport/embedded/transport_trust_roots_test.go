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

package embedded

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

func (m *mockService) TrustRootList(context.Context, *transport.TrustRootListRequest) (*transport.TrustRootListResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.TrustRootListResponse{}, nil
}

func (m *mockService) TrustRootGet(context.Context, *transport.TrustRootRequest) (*transport.TrustRoot, error) {
	return m.trustRoot()
}

func (m *mockService) TrustRootImport(context.Context, *transport.TrustRootImportRequest) (*transport.TrustRootImportResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.TrustRootImportResponse{}, nil
}

func (m *mockService) TrustRootQuarantine(context.Context, *transport.TrustRootRequest) (*transport.TrustRoot, error) {
	return m.trustRoot()
}

func (m *mockService) TrustRootRemove(context.Context, *transport.TrustRootRequest) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

// trustRoot answers a root-returning trust-root method.
func (m *mockService) trustRoot() (*transport.TrustRoot, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.TrustRoot{}, nil
}

// trustRootCalls returns one call per trust-root method of svc.
func trustRootCalls(ctx context.Context, svc transport.TrustRootService) map[string]func() error {
	ref := &transport.TrustRootRequest{Fingerprint: "ab"}
	return map[string]func() error{
		"list": func() error {
			_, err := svc.TrustRootList(ctx, &transport.TrustRootListRequest{})
			return err
		},
		"get": func() error {
			_, err := svc.TrustRootGet(ctx, ref)
			return err
		},
		"import": func() error {
			_, err := svc.TrustRootImport(ctx, &transport.TrustRootImportRequest{PEM: "pem"})
			return err
		},
		"quarantine": func() error {
			_, err := svc.TrustRootQuarantine(ctx, ref)
			return err
		},
		"remove": func() error { return svc.TrustRootRemove(ctx, ref) },
	}
}

// TestTrustRoot_PassesErrorsThrough proves every trust-root method returns
// the service's error unchanged, and its answer when it succeeds.
func TestTrustRoot_PassesErrorsThrough(t *testing.T) {
	ok, err := New(&mockService{})
	require.NoError(t, err)
	failing, err := New(&mockService{shouldFail: true})
	require.NoError(t, err)
	for name, call := range trustRootCalls(context.Background(), ok) {
		t.Run(name, func(t *testing.T) { assert.NoError(t, call()) })
	}
	for name, call := range trustRootCalls(context.Background(), failing) {
		t.Run(name+" fails", func(t *testing.T) { assert.ErrorIs(t, call(), errMock) })
	}
}

// TestTrustRoot_NotConnected proves every trust-root method refuses once the
// transport is closed.
func TestTrustRoot_NotConnected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	require.NoError(t, tr.Close())
	for name, call := range trustRootCalls(context.Background(), tr) {
		t.Run(name, func(t *testing.T) { assert.ErrorIs(t, call(), ErrNotConnected) })
	}
}
