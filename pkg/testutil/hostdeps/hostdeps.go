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

// Package hostdeps builds the in-memory dependencies an embedding host
// supplies to pkg/compose and pkg/apimodule, for tests: a software-backed
// XKMSService, an initialized tenant barrier registry, a platform sealer, a
// PCR reader and a CA configuration. Everything runs in memory.
package hostdeps

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/pinadapter"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/barriertest"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// BackendName is the software backend's name in the service NewService
// builds. It matches the CA identity's default store type.
const BackendName = "software"

// NewService initializes the process XKMSService with one in-memory
// software backend and returns it. The service is reset when t ends.
func NewService(t *testing.T) *xkms.XKMSService {
	t.Helper()
	xkms.Reset()
	t.Cleanup(xkms.Reset)

	kp, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
	require.NoError(t, err)
	backend, err := xkms.New(&xkms.BackendConfig{Backend: kp, CertStorage: storage.New()})
	require.NoError(t, err)
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{BackendName: backend},
		DefaultBackend: BackendName,
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)
	return svc
}

// NewBarrierRegistry returns a tenant barrier registry over an initialized,
// unsealed in-memory system barrier.
func NewBarrierRegistry(t *testing.T) *seal.BarrierRegistry {
	t.Helper()
	return barriertest.NewRegistry(t)
}

// RegisterTenant registers tenantID in registry with an initialized,
// unsealed tenant barrier.
func RegisterTenant(t *testing.T, registry *seal.BarrierRegistry, tenantID string) {
	t.Helper()
	barriertest.RegisterTenant(t, registry, tenantID)
}

// NewPINBackend returns an in-memory software PIN backend with soPIN and
// userPIN provisioned.
func NewPINBackend(t *testing.T, soPIN, userPIN string) qrdbsdk.PINBackend {
	t.Helper()
	pinStore, err := pinadapter.New(storage.New())
	require.NoError(t, err)
	backend, err := qrdbsdk.NewSoftwareBackend(pinStore, qrdbsdk.AutoDetectHashConfig())
	require.NoError(t, err)
	require.NoError(t, backend.SetSOPIN("", soPIN))
	require.NoError(t, backend.SetUserPIN(soPIN, userPIN))
	return backend
}

// NewCAConfig returns a single-identity software ECDSA root CA
// configuration named commonName.
func NewCAConfig(commonName string) *ca.MultiIdentityCAConfig {
	return &ca.MultiIdentityCAConfig{
		SelectedCA:          0,
		DefaultValidityDays: 365,
		Identity: []ca.Identity{{
			IsRoot:  true,
			Valid:   1,
			Subject: ca.Subject{CommonName: commonName, Organization: "Host", Country: "US"},
			Keys: []*types.KeyConfig{{
				KeyAlgorithm: types.AlgorithmECDSA,
				ECCConfig:    &types.ECCConfig{Curve: types.CurveP256},
			}},
		}},
	}
}

// ErrNilSealedData is returned by Sealer.Unseal for a nil envelope.
var ErrNilSealedData = errors.New("hostdeps: sealed data is nil")

// Sealer is an AES-256-GCM types.Sealer over a random in-memory key,
// standing in for a host's hardware sealer. Like a TPM sealer it carries its
// own key, so it seals with nil options.
type Sealer struct {
	aead cipher.AEAD
}

// Compile-time interface check.
var _ types.Sealer = (*Sealer)(nil)

// NewSealer returns a Sealer over a fresh random key.
func NewSealer(t *testing.T) *Sealer {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	// NewGCMWithRandomNonce generates the nonce and carries it in the
	// ciphertext: the only GCM a fips140=only process may build.
	aead, err := cipher.NewGCMWithRandomNonce(block)
	require.NoError(t, err)
	return &Sealer{aead: aead}
}

// Seal encrypts data under the sealer's key, binding opts.AAD when given.
func (s *Sealer) Seal(_ context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
	var aad []byte
	if opts != nil {
		aad = opts.AAD
	}
	return &types.SealedData{
		Backend:    types.BackendTypeSoftware,
		Ciphertext: s.aead.Seal(nil, nil, data, aad),
	}, nil
}

// Unseal decrypts data sealed by Seal. Like every production sealer it
// reports sealed data that is not its own, malformed or fails the AEAD as
// types.ErrSealedDataAuthentication, and a cancelled context as itself.
func (s *Sealer) Unseal(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	if sealed == nil {
		return nil, ErrNilSealedData
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// The nonce travels inside the ciphertext, so a separate one is foreign.
	if sealed.Backend != types.BackendTypeSoftware || len(sealed.Nonce) != 0 {
		return nil, types.SealedDataAuthenticationError("hostdeps: not a sealed value of this sealer", nil)
	}
	var aad []byte
	if opts != nil {
		aad = opts.AAD
	}
	plaintext, err := s.aead.Open(nil, nil, sealed.Ciphertext, aad)
	if err != nil {
		return nil, types.SealedDataAuthenticationError("hostdeps: AES-GCM open", err)
	}
	return plaintext, nil
}

// CanSeal reports that the sealer is usable.
func (s *Sealer) CanSeal() bool { return true }
