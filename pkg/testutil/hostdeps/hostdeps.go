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
	"log/slog"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/pinadapter"
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
	backend, err := storage.NewMemoryBackend()
	require.NoError(t, err)
	barrier, err := seal.NewBarrier(slog.Default(), backend, seal.BarrierConfig{
		RootKeyPath:     "root-key",
		PreferenceOrder: []seal.StrategyID{seal.StrategyPassphrase},
	}, seal.NewSoftwareStrategy())
	require.NoError(t, err)

	creds := seal.MustCredentials([]byte("host-barrier-passphrase"))
	defer creds.Secret.Destroy()
	require.NoError(t, barrier.Initialize(context.Background(), creds))

	registry, err := seal.NewBarrierRegistry(barrier)
	require.NoError(t, err)
	return registry
}

// RegisterTenant registers tenantID in registry with an initialized,
// unsealed tenant barrier.
func RegisterTenant(t *testing.T, registry *seal.BarrierRegistry, tenantID string) {
	t.Helper()
	_, err := registry.RegisterTenant(tenantID)
	require.NoError(t, err)
	creds := seal.MustCredentials([]byte(tenantID + "-passphrase"))
	defer creds.Secret.Destroy()
	require.NoError(t, registry.InitializeTenant(context.Background(), tenantID, creds))
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

// PCRReader is a PCR reader returning fixed digests, standing in for a
// host's TPM.
type PCRReader map[int][]byte

// ReadPCRs returns the fixed digest of every requested index.
func (r PCRReader) ReadPCRs(_ string, indices []int) (map[int][]byte, error) {
	out := make(map[int][]byte, len(indices))
	for _, i := range indices {
		out[i] = r[i]
	}
	return out, nil
}

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
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)
	return &Sealer{aead: aead}
}

// Seal encrypts data under the sealer's key.
func (s *Sealer) Seal(_ context.Context, data []byte, _ *types.SealOptions) (*types.SealedData, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return &types.SealedData{
		Backend:    types.BackendTypeSoftware,
		Ciphertext: s.aead.Seal(nil, nonce, data, nil),
		Nonce:      nonce,
	}, nil
}

// Unseal decrypts data sealed by Seal.
func (s *Sealer) Unseal(_ context.Context, sealed *types.SealedData, _ *types.UnsealOptions) ([]byte, error) {
	return s.aead.Open(nil, sealed.Nonce, sealed.Ciphertext, nil)
}

// CanSeal reports that the sealer is usable.
func (s *Sealer) CanSeal() bool { return true }
