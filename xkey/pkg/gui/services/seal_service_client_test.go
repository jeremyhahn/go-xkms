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

package services

import (
	"context"
	"errors"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// SetLocalClient
// ---------------------------------------------------------------------------

func TestSealService_SetLocalClient(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())

	mc := &sealMockClient{
		canSealFn: func(_ context.Context, backend string) (*transport.CanSealResponse, error) {
			return &transport.CanSealResponse{CanSeal: true, Backend: backend}, nil
		},
	}

	// No clients configured yet -- getClient must fail.
	_, err := svc.getClient()
	require.True(t, errors.Is(err, ErrSealNoClient))

	// Set the local client and verify getClient returns it.
	svc.SetLocalClient(mc)
	got, err := svc.getClient()
	require.NoError(t, err)
	assert.Equal(t, mc, got, "getClient should return the local client")
}

func TestSealService_SetLocalClient_Nil(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())

	mc := &sealMockClient{
		canSealFn: func(_ context.Context, backend string) (*transport.CanSealResponse, error) {
			return &transport.CanSealResponse{CanSeal: true, Backend: backend}, nil
		},
	}

	// Set, then clear the local client.
	svc.SetLocalClient(mc)
	got, err := svc.getClient()
	require.NoError(t, err)
	assert.Equal(t, mc, got)

	svc.SetLocalClient(nil)
	_, err = svc.getClient()
	require.True(t, errors.Is(err, ErrSealNoClient),
		"clearing localClient should cause getClient to return ErrSealNoClient")
}

// ---------------------------------------------------------------------------
// getClient priority
// ---------------------------------------------------------------------------

func TestSealService_GetClient_PrefersRemote(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())

	localClient := &sealMockClient{
		canSealFn: func(_ context.Context, backend string) (*transport.CanSealResponse, error) {
			return &transport.CanSealResponse{CanSeal: false, Backend: backend}, nil
		},
	}
	remoteClient := &sealMockClient{
		canSealFn: func(_ context.Context, backend string) (*transport.CanSealResponse, error) {
			return &transport.CanSealResponse{CanSeal: true, Backend: backend}, nil
		},
	}

	svc.SetLocalClient(localClient)
	svc.SetClientFunc(func() xkms.Client { return remoteClient })

	got, err := svc.getClient()
	require.NoError(t, err)
	assert.Equal(t, remoteClient, got,
		"getClient must prefer the remote client when both are available")
}

func TestSealService_GetClient_FallsBackToLocal(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())

	localClient := &sealMockClient{
		canSealFn: func(_ context.Context, backend string) (*transport.CanSealResponse, error) {
			return &transport.CanSealResponse{CanSeal: true, Backend: backend}, nil
		},
	}

	// Remote clientFunc is set but returns nil (server disconnected).
	svc.SetLocalClient(localClient)
	svc.SetClientFunc(func() xkms.Client { return nil })

	got, err := svc.getClient()
	require.NoError(t, err)
	assert.Equal(t, localClient, got,
		"getClient must fall back to localClient when remote returns nil")
}

func TestSealService_GetClient_NoClients(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())

	// Neither clientFunc nor localClient is set.
	_, err := svc.getClient()
	require.True(t, errors.Is(err, ErrSealNoClient),
		"getClient must return ErrSealNoClient when neither client is available")
}

// ---------------------------------------------------------------------------
// CanSeal with local client
// ---------------------------------------------------------------------------

func TestSealService_CanSeal_WithLocalClient(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())

	// Default backend is tpm2; configure the local client to report it
	// as sealable.
	mc := &sealMockClient{
		canSealFn: func(_ context.Context, backend string) (*transport.CanSealResponse, error) {
			if backend == string(types.BackendTypeTPM2) {
				return &transport.CanSealResponse{CanSeal: true, Backend: backend}, nil
			}
			return &transport.CanSealResponse{CanSeal: false, Backend: backend}, nil
		},
	}
	svc.SetLocalClient(mc)

	canSeal, err := svc.CanSeal()
	require.NoError(t, err)
	assert.True(t, canSeal,
		"CanSeal should return true when the local client reports the default backend as sealable")
}

// ---------------------------------------------------------------------------
// AvailableSealers with local client
// ---------------------------------------------------------------------------

func TestSealService_AvailableSealers_WithLocalClient(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())

	// Local client reports only the software backend as available.
	mc := &sealMockClient{
		canSealFn: func(_ context.Context, backend string) (*transport.CanSealResponse, error) {
			if backend == string(types.BackendTypeSoftware) {
				return &transport.CanSealResponse{CanSeal: true, Backend: backend}, nil
			}
			return &transport.CanSealResponse{CanSeal: false, Backend: backend}, nil
		},
	}
	svc.SetLocalClient(mc)

	sealers := svc.AvailableSealers()
	require.NotEmpty(t, sealers, "AvailableSealers should return at least one entry")

	// Find the software backend and verify it is marked available.
	var softwareFound bool
	for _, si := range sealers {
		if si.ID == string(types.BackendTypeSoftware) {
			assert.True(t, si.Available,
				"software backend should be available when local client reports CanSeal=true")
			softwareFound = true
		} else {
			assert.False(t, si.Available,
				"non-software backends should not be available")
		}
	}
	assert.True(t, softwareFound,
		"AvailableSealers must include the software backend entry")
}
