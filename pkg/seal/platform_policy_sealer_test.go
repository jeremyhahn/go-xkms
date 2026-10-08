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

package seal

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// errRecordingSealerRefused is the failure recordingSealer returns when told
// to refuse.
var errRecordingSealerRefused = errors.New("recording sealer: refused")

// recordingSealer records the options each call received and either echoes
// the data back or refuses.
type recordingSealer struct {
	refuse     bool
	sealOpts   *types.SealOptions
	unsealOpts *types.UnsealOptions
}

func (r *recordingSealer) CanSeal() bool { return !r.refuse }

func (r *recordingSealer) Seal(_ context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
	r.sealOpts = opts
	if r.refuse {
		return nil, errRecordingSealerRefused
	}
	return &types.SealedData{Backend: types.BackendTypeTPM2, Ciphertext: data}, nil
}

func (r *recordingSealer) Unseal(_ context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	r.unsealOpts = opts
	if r.refuse {
		return nil, errRecordingSealerRefused
	}
	return sealed.Ciphertext, nil
}

// TestPlatformPolicySealer_OwnsKeyIdentity proves the sealer replaces the
// caller's key attributes with its own CN, the Platform SRK parent and the
// platform policy on both paths, while passing the caller's AAD through.
func TestPlatformPolicySealer_OwnsKeyIdentity(t *testing.T) {
	inner := &recordingSealer{}
	psrk := &types.KeyAttributes{CN: "psrk"}
	sealer := NewPlatformPolicySealer(inner, "object-cn", psrk)
	require.True(t, sealer.CanSeal())

	aad := []byte("record")
	sealed, err := sealer.Seal(context.Background(), []byte("secret"),
		&types.SealOptions{AAD: aad, KeyAttributes: &types.KeyAttributes{CN: "caller-cn"}})
	require.NoError(t, err)
	require.Equal(t, "object-cn", inner.sealOpts.KeyAttributes.CN)
	require.Same(t, psrk, inner.sealOpts.KeyAttributes.Parent)
	require.Equal(t, types.TPMPolicyPlatform, inner.sealOpts.KeyAttributes.TPMPolicy)
	require.Equal(t, aad, inner.sealOpts.AAD)

	got, err := sealer.Unseal(context.Background(), sealed, &types.UnsealOptions{AAD: aad})
	require.NoError(t, err)
	require.Equal(t, []byte("secret"), got)
	require.Equal(t, "object-cn", inner.unsealOpts.KeyAttributes.CN)
	require.Same(t, psrk, inner.unsealOpts.KeyAttributes.Parent)
	require.Equal(t, types.TPMPolicyPlatform, inner.unsealOpts.KeyAttributes.TPMPolicy)
	require.Equal(t, aad, inner.unsealOpts.AAD)
	require.NotSame(t, inner.sealOpts.KeyAttributes, inner.unsealOpts.KeyAttributes,
		"each call must get fresh attributes the TPM library may mutate")

	_, err = sealer.Seal(context.Background(), []byte("no options"), nil)
	require.NoError(t, err)
	require.Nil(t, inner.sealOpts.AAD)
	_, err = sealer.Unseal(context.Background(), sealed, nil)
	require.NoError(t, err)
	require.Nil(t, inner.unsealOpts.AAD)
}

// TestPlatformPolicySealer_PropagatesFailures proves an inner refusal is
// returned unchanged rather than masked.
func TestPlatformPolicySealer_PropagatesFailures(t *testing.T) {
	sealer := NewPlatformPolicySealer(&recordingSealer{refuse: true}, "object-cn", nil)
	require.False(t, sealer.CanSeal())

	_, err := sealer.Seal(context.Background(), []byte("secret"), nil)
	require.ErrorIs(t, err, errRecordingSealerRefused)

	_, err = sealer.Unseal(context.Background(), &types.SealedData{}, nil)
	require.ErrorIs(t, err, errRecordingSealerRefused)
}
