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

package services

import (
	"crypto/x509"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cloudSealKeyAttrs mirrors sdk/go.SealKeyAttributes for the given store,
// avoiding a direct dependency on the (unexported to this package's tests)
// production helper.
func cloudSealKeyAttrs(store xkms.StoreType) *xkms.KeyAttributes {
	return &xkms.KeyAttributes{
		CN:                 xkms.SealKeyCN,
		StoreType:          store,
		KeyType:            xkms.KeyTypeEncryption,
		KeyAlgorithm:       x509.UnknownPublicKeyAlgorithm,
		SymmetricAlgorithm: xkms.SymmetricAES256GCM,
	}
}

// TestBarrierService_CloudKMSStrategy_UnavailableWithoutFunc proves every
// cloud KMS strategy ID is unavailable until SetCloudKMSStrategyFunc is
// called, matching how TPM2 requires SetTPMSealerFunc.
func TestBarrierService_CloudKMSStrategy_UnavailableWithoutFunc(t *testing.T) {
	for _, id := range []xkms.StrategyID{xkms.StrategyAWSKMS, xkms.StrategyGCPKMS, xkms.StrategyAzureKV, xkms.StrategyVault} {
		t.Run(string(id), func(t *testing.T) {
			svc := newTestBarrierService(t)
			err := svc.Initialize("", string(id))
			require.Error(t, err)
			var unavail *ErrBarrierStrategyUnavailable
			require.ErrorAs(t, err, &unavail)
		})
	}
}

// TestBarrierService_CloudKMSStrategy_InitUnsealRoundTrip proves that once a
// cloud KMS strategy is injected via SetCloudKMSStrategyFunc, Initialize and
// a fresh Unseal both succeed and the barrier reports the injected strategy
// as hardware-backed -- the same round trip a real AWS/GCP/Azure/Vault
// backend goes through, using xkms.NewCloudKMSStrategy (the same
// constructor sdk/go.BuildCloudKMSStrategy uses) over a mock sealer so the
// test needs no live cloud endpoint.
func TestBarrierService_CloudKMSStrategy_InitUnsealRoundTrip(t *testing.T) {
	dataDir := t.TempDir()
	sealer := &mockSealer{canSeal: true}
	keyAttrs := cloudSealKeyAttrs(xkms.StoreAWSKMS)

	newStrategy := func() xkms.SealingStrategy {
		return xkms.NewCloudKMSStrategy(xkms.StrategyAWSKMS, sealer, keyAttrs, nil)
	}

	svc := NewBarrierService(dataDir, testLogger())
	svc.SetCloudKMSStrategyFunc(func(_ string) (xkms.SealingStrategy, error) {
		return newStrategy(), nil
	})

	require.NoError(t, svc.Initialize("", string(xkms.StrategyAWSKMS)))
	require.True(t, svc.IsUnsealed())

	status := svc.Status()
	assert.Equal(t, xkms.StrategyAWSKMS, status.Strategy)
	assert.True(t, status.HardwareBacked)

	require.NoError(t, svc.Seal())
	require.False(t, svc.IsUnsealed())

	// A fresh BarrierService (simulating a new process) must be able to
	// unseal against the same persisted root key once the cloud KMS
	// strategy function is wired again.
	svc2 := NewBarrierService(dataDir, testLogger())
	svc2.SetCloudKMSStrategyFunc(func(_ string) (xkms.SealingStrategy, error) {
		return newStrategy(), nil
	})
	require.NoError(t, svc2.Unseal("", string(xkms.StrategyAWSKMS)))
	require.True(t, svc2.IsUnsealed())
}

// TestBarrierService_CloudKMSStrategy_FuncErrorPropagates proves that an
// error returned by the injected cloud KMS strategy function -- e.g. a
// missing-credentials failure while building the backend -- surfaces from
// Initialize/Unseal rather than being swallowed.
func TestBarrierService_CloudKMSStrategy_FuncErrorPropagates(t *testing.T) {
	svc := newTestBarrierService(t)
	buildErr := &ErrBarrierStrategyUnavailable{Strategy: string(xkms.StrategyVault)}
	svc.SetCloudKMSStrategyFunc(func(_ string) (xkms.SealingStrategy, error) {
		return nil, buildErr
	})

	err := svc.Initialize("", string(xkms.StrategyVault))
	require.Error(t, err)
	assert.ErrorIs(t, err, buildErr)
}
