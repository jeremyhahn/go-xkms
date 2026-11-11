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

//go:build awskms

package xkms

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend/awskms"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// TestSignCoRIM_RefusesAReleaseKeyAWSKMSCannotScope proves first use on AWS
// KMS, whose keys carry no tenant, refuses before any key is created, so no
// retry creates another remote key or replaces the shared release metadata.
func TestSignCoRIM_RefusesAReleaseKeyAWSKMSCannotScope(t *testing.T) {
	var created atomic.Int32
	client := &awskms.MockKMSClient{
		CreateKeyFunc: func(context.Context, *kms.CreateKeyInput, ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
			created.Add(1)
			return nil, errors.New("mock: CreateKey reached")
		},
	}
	provider, err := awskms.NewBackendWithClient(&awskms.Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}, client)
	require.NoError(t, err)
	Reset()
	t.Cleanup(Reset)
	b, err := New(&BackendConfig{Backend: provider, CertStorage: storage.New()})
	require.NoError(t, err)
	require.NoError(t, Initialize(&ServiceConfig{Backends: map[string]Backend{"awskms": b}, DefaultBackend: "awskms"}))
	svc, err := Get()
	require.NoError(t, err)
	wireKeyVersionStore(t)
	ctx := withSigningKeys(t, svc, corimSignPermission)

	for range 2 {
		_, err := svc.SignCoRIM(ctx, signCoRIMRequest(t))
		var provision *ReleaseKeyProvisionError
		require.ErrorAs(t, err, &provision)
		assert.ErrorIs(t, err, ErrReleaseKeyBackendUnsupported)
		assert.Equal(t, int32(0), created.Load(), "no AWS key is created")
	}
}
