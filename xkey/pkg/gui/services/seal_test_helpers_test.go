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
	"testing"

	tpm2pkg "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// ---------------------------------------------------------------------------
// sealMockTPM -- backward-compatible mock TPM for seal service tests
// ---------------------------------------------------------------------------

// sealMockTPM embeds the base mockTPM and adds configurable seal/unseal/canSeal
// behavior. It is used by other test files (auto_unseal, setup_wizard, etc.)
// that construct a SealService as a dependency.
type sealMockTPM struct {
	mockTPM
	canSeal    bool
	sealErr    error
	unsealErr  error
	sealedData []byte // optional: data returned by Seal
}

func (m *sealMockTPM) Seal(_ context.Context, data []byte, _ *types.SealOptions) (*types.SealedData, error) {
	if m.sealErr != nil {
		return nil, m.sealErr
	}
	ciphertext := data
	if m.sealedData != nil {
		ciphertext = m.sealedData
	}
	return &types.SealedData{
		Backend:    types.BackendTypeTPM2,
		Ciphertext: ciphertext,
		TPMPublic:  []byte("tpm-public"),
		TPMPrivate: []byte("tpm-private"),
	}, nil
}

func (m *sealMockTPM) Unseal(_ context.Context, sealed *types.SealedData, _ *types.UnsealOptions) ([]byte, error) {
	if m.unsealErr != nil {
		return nil, m.unsealErr
	}
	return sealed.Ciphertext, nil
}

func (m *sealMockTPM) CanSeal() bool {
	return m.canSeal
}

// defaultSealMock returns a sealMockTPM with canSeal=true and no errors.
func defaultSealMock() *sealMockTPM {
	return &sealMockTPM{
		mockTPM: *defaultMockTPM(),
		canSeal: true,
	}
}

// sealMockClientFromTPM creates a sealMockClient whose Seal/Unseal/CanSeal
// behavior delegates to the given sealMockTPM. This is the bridge between
// the old mock-TPM test pattern and the new SDK client architecture.
func sealMockClientFromTPM(mock *sealMockTPM) *sealMockClient {
	return &sealMockClient{
		sealFn: func(_ context.Context, req *transport.SealRequest) (*transport.SealResponse, error) {
			if mock.sealErr != nil {
				return nil, mock.sealErr
			}
			ciphertext := req.Data
			if mock.sealedData != nil {
				ciphertext = mock.sealedData
			}
			return &transport.SealResponse{
				Backend:    req.Backend,
				Ciphertext: ciphertext,
				TPMPublic:  []byte("tpm-public"),
				TPMPrivate: []byte("tpm-private"),
			}, nil
		},
		unsealFn: func(_ context.Context, req *transport.UnsealRequest) (*transport.UnsealResponse, error) {
			if mock.unsealErr != nil {
				return nil, mock.unsealErr
			}
			return &transport.UnsealResponse{
				Plaintext: req.Ciphertext,
			}, nil
		},
		canSealFn: func(_ context.Context, backend string) (*transport.CanSealResponse, error) {
			return &transport.CanSealResponse{CanSeal: mock.canSeal, Backend: backend}, nil
		},
	}
}

// wireSealMockClient wires a mock SDK client derived from the given
// sealMockTPM into the given SealService. This is used by tests that
// construct their own SealService and need to also set up SDK routing.
func wireSealMockClient(svc *SealService, mock *sealMockTPM) {
	mc := sealMockClientFromTPM(mock)
	svc.SetClientFunc(func() xkms.Client { return mc })
}

// newSealServiceWithMock creates a SealService wired to a mock SDK client
// whose Seal/Unseal/CanSeal behavior delegates to the given sealMockTPM.
// It also sets the TPMAccessor so that tests needing PCR/policy operations
// still work.
func newSealServiceWithMock(t *testing.T, mock *sealMockTPM) *SealService {
	t.Helper()

	svc := NewSealService(t.TempDir())
	wireSealMockClient(svc, mock)
	svc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule { return mock }))
	svc.SetContext(context.Background())

	return svc
}
