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

package clusterca

import (
	"context"
	"encoding/asn1"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

type stubProvider struct {
	secret *ProvisionedSecret
	err    error
}

func (p *stubProvider) ProvisionFor(context.Context, *NodeSecretRequest) (*ProvisionedSecret, error) {
	return p.secret, p.err
}

// TestSecretDeliveryService_Deliver verifies the orchestration collects non-nil
// material from every provider and surfaces provider errors.
func TestSecretDeliveryService_Deliver(t *testing.T) {
	ctx := context.Background()
	oid := asn1.ObjectIdentifier{1, 2, 3}

	// No providers → HasProviders false, empty delivery.
	empty := NewSecretDeliveryService(nil, nil)
	require.False(t, empty.HasProviders())
	got, err := empty.Deliver(ctx, &NodeSecretRequest{})
	require.NoError(t, err)
	require.Empty(t, got)

	// Two providers, one with nothing, one with material.
	svc := NewSecretDeliveryService(nil, nil,
		&stubProvider{secret: nil},
		&stubProvider{secret: &ProvisionedSecret{OID: oid, Data: []byte("m")}},
		nil, // ignored
	)
	require.True(t, svc.HasProviders())
	got, err = svc.Deliver(ctx, &NodeSecretRequest{})
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.True(t, got[0].OID.Equal(oid))

	// A provider error aborts.
	failing := NewSecretDeliveryService(nil, nil, &stubProvider{err: errors.New("boom")})
	_, err = failing.Deliver(ctx, &NodeSecretRequest{})
	require.Error(t, err)
}
