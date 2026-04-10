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

package tpm2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAttestKey_NilAttributes(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mock := &mockTPM{
		ssrkAttrsValue:      &types.KeyAttributes{CN: "ssrk"},
		parsePublicKeyValue: &ecKey.PublicKey,
	}

	b := &Backend{
		tpm:        mock,
		keyBackend: &mockKeyBackend{},
		logger:     slog.Default(),
		srkAttrs:   &types.KeyAttributes{CN: "ssrk"},
		tracker:    backend.NewMemoryAEADTracker(),
	}

	result, err := b.AttestKey(nil, []byte("nonce"))
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrInvalidKeyAttributes)
}

func TestAttestKey_ClosedBackend(t *testing.T) {
	mock := &mockTPM{
		ssrkAttrsValue: &types.KeyAttributes{CN: "ssrk"},
	}

	b := &Backend{
		tpm:        mock,
		keyBackend: &mockKeyBackend{},
		logger:     slog.Default(),
		srkAttrs:   &types.KeyAttributes{CN: "ssrk"},
		tracker:    backend.NewMemoryAEADTracker(),
		closed:     true,
	}

	attrs := &types.KeyAttributes{CN: "test-key"}
	result, err := b.AttestKey(attrs, []byte("nonce"))
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

func TestAttestKey_CertifyKeyError(t *testing.T) {
	certifyErr := errors.New("TPM2_Certify command failed")
	mock := &mockTPM{
		ssrkAttrsValue: &types.KeyAttributes{CN: "ssrk"},
		certifyKeyErr:  certifyErr,
	}

	b := &Backend{
		tpm:        mock,
		keyBackend: &mockKeyBackend{},
		logger:     slog.Default(),
		srkAttrs:   &types.KeyAttributes{CN: "ssrk"},
		tracker:    backend.NewMemoryAEADTracker(),
	}

	attrs := &types.KeyAttributes{CN: "test-key"}
	result, err := b.AttestKey(attrs, []byte("nonce"))
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrAttestationFailed)
}

func TestAttestKey_Success(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	iakKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	certifyResult := &pkgtpm2.CertifyResult{
		CertifyInfo:        []byte("mock-certify-info"),
		Signature:          []byte("mock-signature"),
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		AttestingKeyPublic: &iakKey.PublicKey,
		AttestedKeyPublic:  &ecKey.PublicKey,
		Nonce:              []byte("test-nonce"),
	}

	mock := &mockTPM{
		ssrkAttrsValue:   &types.KeyAttributes{CN: "ssrk"},
		certifyKeyResult: certifyResult,
	}

	b := &Backend{
		tpm:        mock,
		keyBackend: &mockKeyBackend{},
		logger:     slog.Default(),
		srkAttrs:   &types.KeyAttributes{CN: "ssrk"},
		tracker:    backend.NewMemoryAEADTracker(),
	}

	attrs := &types.KeyAttributes{CN: "test-key"}
	nonce := []byte("test-nonce")

	result, err := b.AttestKey(attrs, nonce)
	require.NoError(t, err)
	require.NotNil(t, result)

	stmt, ok := result.(*attestation.AttestationStatement)
	require.True(t, ok, "result should be *attestation.AttestationStatement")

	assert.Equal(t, "tpm2", stmt.Format)
	assert.Equal(t, "tpm2", stmt.Backend)
	assert.Equal(t, x509.ECDSAWithSHA256, stmt.SignatureAlgorithm)
	assert.Equal(t, []byte("mock-certify-info"), stmt.AttestationData)
	assert.Equal(t, []byte("mock-signature"), stmt.Signature)
	assert.Equal(t, nonce, stmt.Nonce)
	assert.NotEmpty(t, stmt.CreatedAt)
	assert.Equal(t, &iakKey.PublicKey, stmt.AttestingKeyPublic)
	assert.Equal(t, &ecKey.PublicKey, stmt.AttestedKeyPublic)
}

func TestAttestKey_InterfaceAssertion(t *testing.T) {
	// Verify that Backend implements AttestingBackend at compile time
	var _ types.AttestingKeyProvider = (*Backend)(nil)
}

func TestCapabilities_AttestationEnabled(t *testing.T) {
	mock := &mockTPM{
		ssrkAttrsValue: &types.KeyAttributes{CN: "ssrk"},
	}

	b := &Backend{
		tpm:        mock,
		keyBackend: &mockKeyBackend{},
		logger:     slog.Default(),
		srkAttrs:   &types.KeyAttributes{CN: "ssrk"},
		tracker:    backend.NewMemoryAEADTracker(),
	}

	caps := b.Capabilities()
	assert.True(t, caps.Attestation, "TPM2 backend should report attestation capability")
	assert.True(t, caps.HardwareBacked, "TPM2 backend should be hardware-backed")
}
