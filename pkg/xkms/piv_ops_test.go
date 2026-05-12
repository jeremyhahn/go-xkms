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
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pivGenStub is a PIVKeyGenerator fixture that returns a fixed signer for
// every slot / CN combination. Used by the Sign tests below.
type pivGenStub struct {
	signer crypto.Signer
}

func (p *pivGenStub) GeneratePIVKey(_ pivcert.PIVSlot, _ string, _ string) (crypto.Signer, error) {
	return p.signer, nil
}

func (p *pivGenStub) GetPIVSigner(_ pivcert.PIVSlot, _ string) (crypto.Signer, error) {
	return p.signer, nil
}

// makeSelfSignedECDSA produces a disposable self-signed certificate for
// seeding mock PIV stores.
func makeSelfSignedECDSA(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
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
	return cert, key
}

// setupPIVForOps installs a fresh PIV manager backed by a mockPIVCertStorage
// and wires a PIVKeyGenerator resolver that always returns genStub.
func setupPIVForOps(t *testing.T, genStub PIVKeyGenerator) *mockPIVCertStorage {
	t.Helper()
	ResetPIV()
	t.Cleanup(func() { ResetPIV() })

	store := newMockPIVCertStorage()
	require.NoError(t, InitializePIV(&PIVManagerConfig{
		Stores: map[string]pivcert.PIVCertificateStorage{
			"software": store,
		},
	}))
	if genStub != nil {
		require.NoError(t, SetPIVBackendResolver(func(_ string) (PIVKeyGenerator, error) {
			return genStub, nil
		}))
	}
	return store
}

// --- SignPIVSlot tests ---

func TestSignPIVSlot_ECDSA_DefaultHash(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_ = setupPIVForOps(t, &pivGenStub{signer: key})

	payload := []byte("platformd-piv-sign")
	resp, err := SignPIVSlot(context.Background(), &transport.PIVSignRequest{
		Backend: "software",
		Slot:    "9c",
		Payload: payload,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "9c", resp.Slot)
	assert.Equal(t, "sha256", resp.HashAlgorithm)
	assert.NotEmpty(t, resp.Signature)

	// Verify signature roundtrips via ecdsa.VerifyASN1.
	digest := sha256.Sum256(payload)
	assert.True(t, ecdsa.VerifyASN1(&key.PublicKey, digest[:], resp.Signature),
		"signature should verify against payload digest")
}

func TestSignPIVSlot_Ed25519RawMessage(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_ = setupPIVForOps(t, &pivGenStub{signer: priv})

	payload := []byte("ed25519 raw message")
	resp, err := SignPIVSlot(context.Background(), &transport.PIVSignRequest{
		Backend: "software",
		Slot:    "9a",
		Payload: payload,
	})
	require.NoError(t, err)
	assert.Empty(t, resp.HashAlgorithm, "Ed25519 signatures carry no hash metadata")
	assert.True(t, ed25519.Verify(pub, payload, resp.Signature),
		"Ed25519 signature should verify on raw payload")
}

func TestSignPIVSlot_PreHashedPayload(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	_ = setupPIVForOps(t, &pivGenStub{signer: key})

	payload := []byte("pre-hashed input")
	digest := sha256.Sum256(payload)

	resp, err := SignPIVSlot(context.Background(), &transport.PIVSignRequest{
		Backend:       "software",
		Slot:          "9c",
		Payload:       digest[:],
		Hashed:        true,
		HashAlgorithm: "sha256",
	})
	require.NoError(t, err)

	// Verify PKCS#1 v1.5 signature.
	require.NoError(t, rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], resp.Signature))
}

func TestSignPIVSlot_EmptyPayload(t *testing.T) {
	_, err := SignPIVSlot(context.Background(), &transport.PIVSignRequest{
		Backend: "software",
		Slot:    "9a",
		Payload: nil,
	})
	assert.ErrorIs(t, err, ErrPIVPayloadRequired)
}

func TestSignPIVSlot_InvalidSlot(t *testing.T) {
	_, err := SignPIVSlot(context.Background(), &transport.PIVSignRequest{
		Backend: "software",
		Slot:    "not-a-slot",
		Payload: []byte("x"),
	})
	assert.ErrorIs(t, err, ErrPIVInvalidSlot)
}

func TestSignPIVSlot_InvalidHashAlgorithm(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_ = setupPIVForOps(t, &pivGenStub{signer: key})

	_, err = SignPIVSlot(context.Background(), &transport.PIVSignRequest{
		Backend:       "software",
		Slot:          "9c",
		Payload:       []byte("x"),
		HashAlgorithm: "md5",
	})
	assert.ErrorIs(t, err, ErrPIVHashAlgorithmInvalid)
}

func TestSignPIVSlot_NotInitialised(t *testing.T) {
	ResetPIV()
	_, err := SignPIVSlot(context.Background(), &transport.PIVSignRequest{
		Backend: "software",
		Slot:    "9a",
		Payload: []byte("x"),
	})
	assert.ErrorIs(t, err, ErrPIVNotInitialized)
}

// --- AttestPIVSlot tests ---

func TestAttestPIVSlot_ReturnsSlotCert(t *testing.T) {
	store := setupPIVForOps(t, nil)
	slotCert, _ := makeSelfSignedECDSA(t, "piv-9a")
	require.NoError(t, store.Store(pivcert.PIVSlotAuthentication, slotCert))

	resp, err := AttestPIVSlot(context.Background(), &transport.PIVAttestRequest{
		Backend: "software",
		Slot:    "9a",
	})
	require.NoError(t, err)
	assert.Equal(t, "9a", resp.Slot)
	assert.NotEmpty(t, resp.Certificate)
	assert.Empty(t, resp.Chain, "no attestation slot cert -> empty chain")
}

func TestAttestPIVSlot_WithAttestationChain(t *testing.T) {
	store := setupPIVForOps(t, nil)
	slotCert, _ := makeSelfSignedECDSA(t, "piv-9c")
	attestCert, _ := makeSelfSignedECDSA(t, "piv-f9")
	require.NoError(t, store.Store(pivcert.PIVSlotDigitalSignature, slotCert))
	require.NoError(t, store.Store(pivcert.PIVSlotAttestation, attestCert))

	resp, err := AttestPIVSlot(context.Background(), &transport.PIVAttestRequest{
		Backend: "software",
		Slot:    "9c",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Certificate)
	assert.NotEmpty(t, resp.Chain, "chain should contain the f9 cert")
}

func TestAttestPIVSlot_AttestationSlotReturnsSelfNoChain(t *testing.T) {
	store := setupPIVForOps(t, nil)
	attestCert, _ := makeSelfSignedECDSA(t, "piv-f9")
	require.NoError(t, store.Store(pivcert.PIVSlotAttestation, attestCert))

	resp, err := AttestPIVSlot(context.Background(), &transport.PIVAttestRequest{
		Backend: "software",
		Slot:    "f9",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Certificate)
	assert.Empty(t, resp.Chain, "attestation slot does not attest to itself")
}

func TestAttestPIVSlot_MissingCert(t *testing.T) {
	_ = setupPIVForOps(t, nil)
	_, err := AttestPIVSlot(context.Background(), &transport.PIVAttestRequest{
		Backend: "software",
		Slot:    "9a",
	})
	assert.ErrorIs(t, err, ErrPIVNoAttestationMaterial)
}

func TestAttestPIVSlot_InvalidSlot(t *testing.T) {
	_ = setupPIVForOps(t, nil)
	_, err := AttestPIVSlot(context.Background(), &transport.PIVAttestRequest{
		Backend: "software",
		Slot:    "bogus",
	})
	assert.ErrorIs(t, err, ErrPIVInvalidSlot)
}

// --- ResetPIVDevice tests ---

func TestResetPIVDevice_ClearsAllCerts(t *testing.T) {
	store := setupPIVForOps(t, nil)
	slotCert, _ := makeSelfSignedECDSA(t, "piv-9a")
	attestCert, _ := makeSelfSignedECDSA(t, "piv-f9")
	require.NoError(t, store.Store(pivcert.PIVSlotAuthentication, slotCert))
	require.NoError(t, store.Store(pivcert.PIVSlotAttestation, attestCert))

	err := ResetPIVDevice(context.Background(), &transport.PIVResetDeviceRequest{
		Backend: "software",
		Confirm: true,
	})
	require.NoError(t, err)

	infos, err := store.List()
	require.NoError(t, err)
	assert.Empty(t, infos, "all slots should be cleared")
}

func TestResetPIVDevice_RequiresConfirm(t *testing.T) {
	store := setupPIVForOps(t, nil)
	slotCert, _ := makeSelfSignedECDSA(t, "piv-9a")
	require.NoError(t, store.Store(pivcert.PIVSlotAuthentication, slotCert))

	err := ResetPIVDevice(context.Background(), &transport.PIVResetDeviceRequest{
		Backend: "software",
		Confirm: false,
	})
	assert.ErrorIs(t, err, ErrPIVResetNotConfirmed)

	// Store should be untouched.
	infos, listErr := store.List()
	require.NoError(t, listErr)
	assert.Len(t, infos, 1)
}

func TestResetPIVDevice_NilRequest(t *testing.T) {
	_ = setupPIVForOps(t, nil)
	err := ResetPIVDevice(context.Background(), nil)
	assert.ErrorIs(t, err, ErrPIVResetNotConfirmed)
}

func TestResetPIVDevice_UnknownBackend(t *testing.T) {
	_ = setupPIVForOps(t, nil)
	err := ResetPIVDevice(context.Background(), &transport.PIVResetDeviceRequest{
		Backend: "not-registered",
		Confirm: true,
	})
	assert.ErrorIs(t, err, ErrPIVBackendNotFound)
}

// --- defaultHashForSigner tests ---

func TestDefaultHashForSigner(t *testing.T) {
	tests := []struct {
		name   string
		signer crypto.Signer
		want   string
	}{
		{
			name: "ecdsa p256 -> sha256",
			signer: func() crypto.Signer {
				k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				return k
			}(),
			want: "sha256",
		},
		{
			name: "ecdsa p384 -> sha384",
			signer: func() crypto.Signer {
				k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				return k
			}(),
			want: "sha384",
		},
		{
			name: "rsa 2048 -> sha256",
			signer: func() crypto.Signer {
				k, _ := rsa.GenerateKey(rand.Reader, 2048)
				return k
			}(),
			want: "sha256",
		},
		{
			name: "ed25519 -> empty",
			signer: func() crypto.Signer {
				_, priv, _ := ed25519.GenerateKey(rand.Reader)
				return priv
			}(),
			want: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := defaultHashForSigner(tc.signer)
			assert.Equal(t, tc.want, got)
		})
	}
}
