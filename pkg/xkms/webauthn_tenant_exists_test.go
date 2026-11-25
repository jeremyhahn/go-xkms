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
	"fmt"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// lookupTenantServicer answers GetTenant with a fixed result.
type lookupTenantServicer struct {
	qrdbsdk.ServiceTenantServicer
	info *qrdbsdk.ServiceTenantInfo
	err  error
}

func (f *lookupTenantServicer) GetTenant(context.Context, string) (*qrdbsdk.ServiceTenantInfo, error) {
	return f.info, f.err
}

func TestWebAuthnTenantExists_FoundTenant(t *testing.T) {
	svc := &XKMSService{}
	svc.SetTenantService(&lookupTenantServicer{info: &qrdbsdk.ServiceTenantInfo{ID: "acme"}})

	ok, err := svc.WebAuthnTenantExists(context.Background(), "acme")
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestWebAuthnTenantExists_MissingTenantIsUnknown(t *testing.T) {
	for name, missing := range map[string]error{
		"sentinel": qrdbsdk.ErrTenantMissing,
		"wrapped":  fmt.Errorf("lookup: %w", qrdbsdk.ErrTenantMissing),
		"deleted":  &TenantDeletedError{},
	} {
		t.Run(name, func(t *testing.T) {
			svc := &XKMSService{}
			svc.SetTenantService(&lookupTenantServicer{err: missing})

			ok, err := svc.WebAuthnTenantExists(context.Background(), "ghost")
			require.NoError(t, err)
			assert.False(t, ok)
		})
	}
}

func TestWebAuthnTenantExists_PropagatesLookupFailure(t *testing.T) {
	storage := errors.New("storage unavailable")
	for name, failure := range map[string]error{
		"storage":  storage,
		"canceled": context.Canceled,
	} {
		t.Run(name, func(t *testing.T) {
			svc := &XKMSService{}
			svc.SetTenantService(&lookupTenantServicer{err: failure})

			ok, err := svc.WebAuthnTenantExists(context.Background(), "acme")
			require.ErrorIs(t, err, failure)
			assert.False(t, ok)
		})
	}
}
