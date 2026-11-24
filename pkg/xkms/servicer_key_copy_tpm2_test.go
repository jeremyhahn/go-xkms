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

package xkms

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// algorithmRecordingProvider records the wrapping algorithm the copy asks the
// destination's GetImportParameters for.
type algorithmRecordingProvider struct {
	*boostIEKeyProvider
	requested []backend.WrappingAlgorithm
}

func (p *algorithmRecordingProvider) GetImportParameters(ctx context.Context, attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
	p.requested = append(p.requested, algorithm)
	return p.boostIEKeyProvider.GetImportParameters(ctx, attrs, algorithm)
}

// TestCopyKey_TPM2DestinationDefaultsToDuplication: a TPM imports only TCG
// duplication blobs, so a copy into a tpm2 backend that names no algorithm
// asks the destination for TPM2_DUPLICATE parameters rather than the RSA-OAEP
// default every other destination gets (ruling 932). An explicit algorithm
// is still passed through unchanged.
func TestCopyKey_TPM2DestinationDefaultsToDuplication(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	srcKP := newBoostIEKeyProvider()
	srcStore := newMockKeyStore("software")
	srcStore.backend = srcKP

	dstKP := &algorithmRecordingProvider{boostIEKeyProvider: newBoostIEKeyProvider()}
	dstStore := newMockKeyStore("tpm-dest")
	dstStore.storeType = types.StoreTPM2
	dstStore.backend = dstKP

	require.NoError(t, Initialize(&ServiceConfig{
		Backends: map[string]Backend{
			"software": srcStore,
			"tpm-dest": dstStore,
		},
		DefaultBackend: "software",
	}))
	svc, err := Get()
	require.NoError(t, err)
	ctx := context.Background()

	boostGenIEKey(t, srcStore, srcKP, &types.KeyAttributes{
		CN:           "sw-key",
		KeyAlgorithm: x509.ECDSA,
		Exportable:   true,
	})

	_, err = svc.CopyKey(ctx, &transport.CopyKeyRequest{
		SourceBackend: "software",
		SourceKeyID:   "sw-key",
		DestBackend:   "tpm-dest",
		DestKeyID:     "sw-key-tpm",
	})
	require.NoError(t, err)
	require.Len(t, dstKP.requested, 1)
	assert.Equal(t, backend.WrappingAlgorithmTPM2Duplicate, dstKP.requested[0])

	_, err = svc.CopyKey(ctx, &transport.CopyKeyRequest{
		SourceBackend: "software",
		SourceKeyID:   "sw-key",
		DestBackend:   "tpm-dest",
		DestKeyID:     "sw-key-tpm-explicit",
		Algorithm:     string(backend.WrappingAlgorithmRSAES_OAEP_SHA_256),
	})
	require.NoError(t, err)
	require.Len(t, dstKP.requested, 2)
	assert.Equal(t, backend.WrappingAlgorithmRSAES_OAEP_SHA_256, dstKP.requested[1])
}
