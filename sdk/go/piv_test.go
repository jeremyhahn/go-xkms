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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	pivbackend "github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sdkPIVKeyGen is a minimal PIVKeyGenerator that returns a fixed signer.
type sdkPIVKeyGen struct {
	key *ecdsa.PrivateKey
}

func (s *sdkPIVKeyGen) GeneratePIVKey(_ pivcert.PIVSlot, _ string, _ string) (crypto.Signer, error) {
	return s.key, nil
}

func (s *sdkPIVKeyGen) GetPIVSigner(_ pivcert.PIVSlot, _ string) (crypto.Signer, error) {
	return s.key, nil
}

// sdkPIVStore is an in-memory PIVCertificateStorage used by the SDK tests.
type sdkPIVStore struct {
	mu    sync.Mutex
	certs map[pivcert.PIVSlot]*x509.Certificate
}

func newSDKPIVStore() *sdkPIVStore {
	return &sdkPIVStore{certs: make(map[pivcert.PIVSlot]*x509.Certificate)}
}

func (s *sdkPIVStore) Store(slot pivcert.PIVSlot, cert *x509.Certificate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.certs[slot] = cert
	return nil
}
func (s *sdkPIVStore) Retrieve(slot pivcert.PIVSlot) (*x509.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.certs[slot]
	if !ok {
		return nil, errors.New("not found")
	}
	return c, nil
}
func (s *sdkPIVStore) Delete(slot pivcert.PIVSlot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.certs[slot]; !ok {
		return errors.New("not found")
	}
	delete(s.certs, slot)
	return nil
}
func (s *sdkPIVStore) List() ([]pivcert.PIVSlotInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]pivcert.PIVSlotInfo, 0, len(s.certs))
	for slot := range s.certs {
		out = append(out, pivcert.PIVSlotInfo{Slot: slot})
	}
	return out, nil
}
func (s *sdkPIVStore) Import(_ pivcert.PIVSlot, _ []byte, _ pivcert.CertFormat) error { return nil }
func (s *sdkPIVStore) Export(slot pivcert.PIVSlot, format pivcert.CertFormat) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.certs[slot]
	if !ok {
		return nil, errors.New("not found")
	}
	if format == pivcert.FormatPEM {
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}), nil
	}
	return c.Raw, nil
}
func (s *sdkPIVStore) Close() error                  { return nil }
func (s *sdkPIVStore) Type() pivcert.PIVStorageType  { return "sdk-test" }

// makeSDKTestCert mints a throwaway self-signed cert for the SDK tests.
func makeSDKTestCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// setupSDKPIV installs a PIV manager for use by the SDK re-export tests.
// Returns the underlying store so the test can seed slots.
func setupSDKPIV(t *testing.T, key *ecdsa.PrivateKey) *sdkPIVStore {
	t.Helper()
	pivbackend.ResetPIV()
	t.Cleanup(pivbackend.ResetPIV)

	store := newSDKPIVStore()
	require.NoError(t, pivbackend.InitializePIV(&pivbackend.PIVManagerConfig{
		Stores: map[string]pivcert.PIVCertificateStorage{"software": store},
	}))
	if key != nil {
		require.NoError(t, pivbackend.SetPIVBackendResolver(
			func(_ string) (pivbackend.PIVKeyGenerator, error) {
				return &sdkPIVKeyGen{key: key}, nil
			}))
	}
	return store
}

// TestSDK_SignPIV verifies the SDK re-export of SignPIV produces a valid
// ECDSA signature that the caller can verify with the public key.
func TestSDK_SignPIV(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_ = setupSDKPIV(t, key)

	payload := []byte("hello from SDK")
	resp, err := SignPIV(context.Background(), &PIVSignRequest{
		Backend: "software",
		Slot:    "9a",
		Payload: payload,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "sha256", resp.HashAlgorithm)

	digest := sha256.Sum256(payload)
	assert.True(t, ecdsa.VerifyASN1(&key.PublicKey, digest[:], resp.Signature))
}

// TestSDK_SignPIV_Error verifies the SDK-layer error mapping when the
// payload is empty.
func TestSDK_SignPIV_Error(t *testing.T) {
	_ = setupSDKPIV(t, nil)

	_, err := SignPIV(context.Background(), &PIVSignRequest{
		Backend: "software",
		Slot:    "9a",
	})
	assert.ErrorIs(t, err, ErrPIVPayloadRequired)
}

// TestSDK_AttestPIV returns the slot cert and verifies the re-export
// forwards to the upstream implementation.
func TestSDK_AttestPIV(t *testing.T) {
	store := setupSDKPIV(t, nil)
	require.NoError(t, store.Store(pivcert.PIVSlotAuthentication, makeSDKTestCert(t, "piv-9a")))

	resp, err := AttestPIV(context.Background(), &PIVAttestRequest{
		Backend: "software",
		Slot:    "9a",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Certificate)
	assert.Empty(t, resp.Chain)
}

// TestSDK_AttestPIV_Missing returns ErrPIVNoAttestationMaterial when no
// cert is present.
func TestSDK_AttestPIV_Missing(t *testing.T) {
	_ = setupSDKPIV(t, nil)

	_, err := AttestPIV(context.Background(), &PIVAttestRequest{
		Backend: "software",
		Slot:    "9a",
	})
	assert.ErrorIs(t, err, ErrPIVNoAttestationMaterial)
}

// TestSDK_ResetPIV requires confirmation and clears all slots.
func TestSDK_ResetPIV(t *testing.T) {
	store := setupSDKPIV(t, nil)
	require.NoError(t, store.Store(pivcert.PIVSlotAuthentication, makeSDKTestCert(t, "piv-9a")))
	require.NoError(t, store.Store(pivcert.PIVSlotDigitalSignature, makeSDKTestCert(t, "piv-9c")))

	require.NoError(t, ResetPIV(context.Background(), &PIVResetDeviceRequest{
		Backend: "software",
		Confirm: true,
	}))

	infos, err := store.List()
	require.NoError(t, err)
	assert.Empty(t, infos)
}

// TestSDK_ResetPIV_Unconfirmed rejects calls without Confirm=true.
func TestSDK_ResetPIV_Unconfirmed(t *testing.T) {
	store := setupSDKPIV(t, nil)
	require.NoError(t, store.Store(pivcert.PIVSlotAuthentication, makeSDKTestCert(t, "piv-9a")))

	err := ResetPIV(context.Background(), &PIVResetDeviceRequest{
		Backend: "software",
		Confirm: false,
	})
	assert.ErrorIs(t, err, ErrPIVResetNotConfirmed)

	infos, listErr := store.List()
	require.NoError(t, listErr)
	assert.Len(t, infos, 1, "store must be untouched")
}
