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

package client

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeAuthClient is a minimal auth.Client implementation used only to verify
// that WithAuthClient wires the option's value into the TrustedCA struct.
type fakeAuthClient struct {
	name string
}

func (f *fakeAuthClient) ValidateToken(_ context.Context, token string) (*auth.TokenClaims, error) {
	return &auth.TokenClaims{UserID: f.name, Valid: true}, nil
}

func (f *fakeAuthClient) RefreshToken(_ context.Context, token string) (string, error) {
	return "refreshed-" + token, nil
}

func (f *fakeAuthClient) RevokeToken(_ context.Context, token string) error {
	return nil
}

func TestWithAuthClient_SetsAuthClient(t *testing.T) {
	fake := &fakeAuthClient{name: "test-client"}

	tca, err := New(
		WithCA(newMockCA()),
		WithStorageFactory(newMockStorageFactory()),
		WithAuthClient(fake),
	)
	require.NoError(t, err)
	require.NotNil(t, tca)

	assert.Same(t, fake, tca.authClient)
}

func TestWithAuthClient_NilClient(t *testing.T) {
	tca, err := New(
		WithCA(newMockCA()),
		WithStorageFactory(newMockStorageFactory()),
		WithAuthClient(nil),
	)
	require.NoError(t, err)
	require.NotNil(t, tca)
	assert.Nil(t, tca.authClient)
}
