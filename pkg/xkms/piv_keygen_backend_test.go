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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Mock XKMS Backend ---

type mockXKMSBackend struct {
	generateRSAFunc     func(*types.KeyAttributes) (crypto.PrivateKey, error)
	generateECDSAFunc   func(*types.KeyAttributes) (crypto.PrivateKey, error)
	generateEd25519Func func(*types.KeyAttributes) (crypto.PrivateKey, error)
	signerFunc          func(*types.KeyAttributes) (crypto.Signer, error)

	generateCalls []types.KeyAttributes
	signerCalls   []string
}

func (m *mockXKMSBackend) GenerateRSA(_ context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	m.generateCalls = append(m.generateCalls, *attrs)
	if m.generateRSAFunc != nil {
		return m.generateRSAFunc(attrs)
	}
	return nil, errors.New("not implemented")
}

func (m *mockXKMSBackend) GenerateECDSA(_ context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	m.generateCalls = append(m.generateCalls, *attrs)
	if m.generateECDSAFunc != nil {
		return m.generateECDSAFunc(attrs)
	}
	return nil, errors.New("not implemented")
}

func (m *mockXKMSBackend) GenerateEd25519(_ context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	m.generateCalls = append(m.generateCalls, *attrs)
	if m.generateEd25519Func != nil {
		return m.generateEd25519Func(attrs)
	}
	return nil, errors.New("not implemented")
}

func (m *mockXKMSBackend) Signer(_ context.Context, attrs *types.KeyAttributes) (crypto.Signer, error) {
	m.signerCalls = append(m.signerCalls, attrs.CN)
	if m.signerFunc != nil {
		return m.signerFunc(attrs)
	}
	return nil, errors.New("not implemented")
}

func (m *mockXKMSBackend) GetKey(_ context.Context, _ *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, errors.New("not implemented")
}

func (m *mockXKMSBackend) DeleteKey(_ context.Context, _ *types.KeyAttributes) error {
	return errors.New("not implemented")
}

func (m *mockXKMSBackend) ListKeys(_ context.Context) ([]*types.KeyAttributes, error) {
	return nil, errors.New("not implemented")
}

func (m *mockXKMSBackend) RotateKey(_ context.Context, _ *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, errors.New("not implemented")
}

func (m *mockXKMSBackend) Decrypter(_ context.Context, _ *types.KeyAttributes) (crypto.Decrypter, error) {
	return nil, errors.New("not implemented")
}

func (m *mockXKMSBackend) SaveCert(_ context.Context, _ string, _ *x509.Certificate) error {
	return errors.New("not implemented")
}

func (m *mockXKMSBackend) GetCert(_ context.Context, _ string) (*x509.Certificate, error) {
	return nil, errors.New("not implemented")
}

func (m *mockXKMSBackend) DeleteCert(_ context.Context, _ string) error {
	return errors.New("not implemented")
}

func (m *mockXKMSBackend) SaveCertChain(_ context.Context, _ string, _ []*x509.Certificate) error {
	return errors.New("not implemented")
}

func (m *mockXKMSBackend) GetCertChain(_ context.Context, _ string) ([]*x509.Certificate, error) {
	return nil, errors.New("not implemented")
}

func (m *mockXKMSBackend) ListCerts(_ context.Context) ([]string, error) {
	return nil, errors.New("not implemented")
}

func (m *mockXKMSBackend) CertExists(_ context.Context, _ string) (bool, error) {
	return false, errors.New("not implemented")
}

func (m *mockXKMSBackend) GetTLSCertificate(_ context.Context, _ string, _ *types.KeyAttributes) (tls.Certificate, error) {
	return tls.Certificate{}, errors.New("not implemented")
}

func (m *mockXKMSBackend) GetKeyByID(_ context.Context, _ string) (crypto.PrivateKey, error) {
	return nil, errors.New("not implemented")
}

func (m *mockXKMSBackend) GetSignerByID(_ context.Context, _ string) (crypto.Signer, error) {
	return nil, errors.New("not implemented")
}

func (m *mockXKMSBackend) GetDecrypterByID(_ context.Context, _ string) (crypto.Decrypter, error) {
	return nil, errors.New("not implemented")
}

func (m *mockXKMSBackend) Seal(_ context.Context, _ []byte, _ *types.SealOptions) (*types.SealedData, error) {
	return nil, errors.New("not implemented")
}

func (m *mockXKMSBackend) Unseal(_ context.Context, _ *types.SealedData, _ *types.UnsealOptions) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (m *mockXKMSBackend) CanSeal() bool {
	return false
}

func (m *mockXKMSBackend) KeyProvider() types.KeyProvider {
	return nil
}

func (m *mockXKMSBackend) CertStorage() certstore.CertificateStorageAdapter {
	return nil
}

func (m *mockXKMSBackend) Close() error {
	return nil
}

// Verify interface compliance
var _ Backend = (*mockXKMSBackend)(nil)

// --- Mock with PIVParentProvider ---

type mockXKMSBackendWithParent struct {
	mockXKMSBackend
	parentAttrs    *types.KeyAttributes
	parentAttrsErr error
}

func (m *mockXKMSBackendWithParent) PIVParentAttributes() (*types.KeyAttributes, error) {
	return m.parentAttrs, m.parentAttrsErr
}

// Verify interface compliance
var _ PIVParentProvider = (*mockXKMSBackendWithParent)(nil)

// --- Helper to create a mock signer ---

func newTestECDSASigner(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

// --- Backend PIV key generator tests ---

func TestBackendPIVKeyGenerator_RSA(t *testing.T) {
	signer := newTestECDSASigner(t)

	mock := &mockXKMSBackend{
		generateRSAFunc: func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
			return nil, nil
		},
		signerFunc: func(_ *types.KeyAttributes) (crypto.Signer, error) {
			return signer, nil
		},
	}

	gen := newBackendPIVKeyGenerator(mock, types.StoreSoftware)
	result, err := gen.GeneratePIVKey(pivcert.PIVSlotAuthentication, "rsa2048", "piv-9a")
	require.NoError(t, err)
	assert.Equal(t, signer, result)

	// Verify the attributes passed to GenerateRSA
	require.Len(t, mock.generateCalls, 1)
	assert.Equal(t, "piv-9a", mock.generateCalls[0].CN)
	assert.Equal(t, x509.RSA, mock.generateCalls[0].KeyAlgorithm)
	require.NotNil(t, mock.generateCalls[0].RSAAttributes)
	assert.Equal(t, 2048, mock.generateCalls[0].RSAAttributes.KeySize)
}

// TestBackendPIVKeyGenerator_RSA4096 verifies that the rsa4096 algorithm
// builder correctly sets RSA key attributes with 4096-bit key size.
func TestBackendPIVKeyGenerator_RSA4096(t *testing.T) {
	signer := newTestECDSASigner(t)

	mock := &mockXKMSBackend{
		generateRSAFunc: func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
			return nil, nil
		},
		signerFunc: func(_ *types.KeyAttributes) (crypto.Signer, error) {
			return signer, nil
		},
	}

	gen := newBackendPIVKeyGenerator(mock, types.StoreSoftware)
	result, err := gen.GeneratePIVKey(pivcert.PIVSlotDigitalSignature, "rsa4096", "piv-9c")
	require.NoError(t, err)
	assert.Equal(t, signer, result)

	require.Len(t, mock.generateCalls, 1)
	assert.Equal(t, "piv-9c", mock.generateCalls[0].CN)
	assert.Equal(t, x509.RSA, mock.generateCalls[0].KeyAlgorithm)
	require.NotNil(t, mock.generateCalls[0].RSAAttributes)
	assert.Equal(t, 4096, mock.generateCalls[0].RSAAttributes.KeySize)
}

func TestBackendPIVKeyGenerator_ECDSA(t *testing.T) {
	signer := newTestECDSASigner(t)

	mock := &mockXKMSBackend{
		generateECDSAFunc: func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
			return nil, nil
		},
		signerFunc: func(_ *types.KeyAttributes) (crypto.Signer, error) {
			return signer, nil
		},
	}

	gen := newBackendPIVKeyGenerator(mock, types.StoreSoftware)
	result, err := gen.GeneratePIVKey(pivcert.PIVSlotAuthentication, "ecdsap256", "piv-9a")
	require.NoError(t, err)
	assert.Equal(t, signer, result)

	require.Len(t, mock.generateCalls, 1)
	assert.Equal(t, "piv-9a", mock.generateCalls[0].CN)
	assert.Equal(t, x509.ECDSA, mock.generateCalls[0].KeyAlgorithm)
	require.NotNil(t, mock.generateCalls[0].ECCAttributes)
	assert.Equal(t, elliptic.P256(), mock.generateCalls[0].ECCAttributes.Curve)
}

func TestBackendPIVKeyGenerator_ECDSAP384(t *testing.T) {
	signer := newTestECDSASigner(t)

	mock := &mockXKMSBackend{
		generateECDSAFunc: func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
			return nil, nil
		},
		signerFunc: func(_ *types.KeyAttributes) (crypto.Signer, error) {
			return signer, nil
		},
	}

	gen := newBackendPIVKeyGenerator(mock, types.StoreSoftware)
	result, err := gen.GeneratePIVKey(pivcert.PIVSlotDigitalSignature, "ecdsap384", "piv-9c")
	require.NoError(t, err)
	assert.Equal(t, signer, result)

	require.Len(t, mock.generateCalls, 1)
	assert.Equal(t, x509.ECDSA, mock.generateCalls[0].KeyAlgorithm)
	require.NotNil(t, mock.generateCalls[0].ECCAttributes)
	assert.Equal(t, elliptic.P384(), mock.generateCalls[0].ECCAttributes.Curve)
}

func TestBackendPIVKeyGenerator_Ed25519(t *testing.T) {
	signer := newTestECDSASigner(t)

	mock := &mockXKMSBackend{
		generateEd25519Func: func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
			return nil, nil
		},
		signerFunc: func(_ *types.KeyAttributes) (crypto.Signer, error) {
			return signer, nil
		},
	}

	gen := newBackendPIVKeyGenerator(mock, types.StoreSoftware)
	result, err := gen.GeneratePIVKey(pivcert.PIVSlotKeyManagement, "ed25519", "piv-9d")
	require.NoError(t, err)
	assert.Equal(t, signer, result)

	require.Len(t, mock.generateCalls, 1)
	assert.Equal(t, "piv-9d", mock.generateCalls[0].CN)
	assert.Equal(t, x509.Ed25519, mock.generateCalls[0].KeyAlgorithm)
}

func TestBackendPIVKeyGenerator_InvalidAlgorithm(t *testing.T) {
	mock := &mockXKMSBackend{}

	gen := newBackendPIVKeyGenerator(mock, types.StoreSoftware)
	result, err := gen.GeneratePIVKey(pivcert.PIVSlotAuthentication, "invalid-algo", "piv-9a")
	assert.Nil(t, result)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPIVInvalidAlgorithm)
	assert.Empty(t, mock.generateCalls)
}

func TestBackendPIVKeyGenerator_DefaultAlgorithm(t *testing.T) {
	signer := newTestECDSASigner(t)

	mock := &mockXKMSBackend{
		generateECDSAFunc: func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
			return nil, nil
		},
		signerFunc: func(_ *types.KeyAttributes) (crypto.Signer, error) {
			return signer, nil
		},
	}

	gen := newBackendPIVKeyGenerator(mock, types.StoreSoftware)
	result, err := gen.GeneratePIVKey(pivcert.PIVSlotAuthentication, "", "piv-9a")
	require.NoError(t, err)
	assert.Equal(t, signer, result)

	// Default should be ecdsap256
	require.Len(t, mock.generateCalls, 1)
	assert.Equal(t, x509.ECDSA, mock.generateCalls[0].KeyAlgorithm)
	require.NotNil(t, mock.generateCalls[0].ECCAttributes)
	assert.Equal(t, elliptic.P256(), mock.generateCalls[0].ECCAttributes.Curve)
}

func TestBackendPIVKeyGenerator_GetSignerDelegates(t *testing.T) {
	signer := newTestECDSASigner(t)

	mock := &mockXKMSBackend{
		signerFunc: func(attrs *types.KeyAttributes) (crypto.Signer, error) {
			return signer, nil
		},
	}

	gen := newBackendPIVKeyGenerator(mock, types.StoreSoftware)
	result, err := gen.GetPIVSigner(pivcert.PIVSlotAuthentication, "piv-9a")
	require.NoError(t, err)
	assert.Equal(t, signer, result)

	// Verify Signer was called with the correct CN
	require.Len(t, mock.signerCalls, 1)
	assert.Equal(t, "piv-9a", mock.signerCalls[0])
}

func TestBackendPIVKeyGenerator_PIVParentProvider(t *testing.T) {
	signer := newTestECDSASigner(t)

	parentAttrs := &types.KeyAttributes{
		CN:      "platform-srk",
		KeyType: types.KeyTypeStorage,
	}

	mock := &mockXKMSBackendWithParent{
		mockXKMSBackend: mockXKMSBackend{
			generateECDSAFunc: func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
				return nil, nil
			},
			signerFunc: func(_ *types.KeyAttributes) (crypto.Signer, error) {
				return signer, nil
			},
		},
		parentAttrs: parentAttrs,
	}

	gen := newBackendPIVKeyGenerator(mock, types.StoreSoftware)
	result, err := gen.GeneratePIVKey(pivcert.PIVSlotAuthentication, "ecdsap256", "piv-9a")
	require.NoError(t, err)
	assert.Equal(t, signer, result)

	// Verify parent was set on the generated attributes
	require.Len(t, mock.generateCalls, 1)
	require.NotNil(t, mock.generateCalls[0].Parent)
	assert.Equal(t, "platform-srk", mock.generateCalls[0].Parent.CN)
	assert.Equal(t, types.KeyTypeStorage, mock.generateCalls[0].Parent.KeyType)
}

func TestBackendPIVKeyGenerator_NoPIVParentProvider(t *testing.T) {
	signer := newTestECDSASigner(t)

	// Use plain mockXKMSBackend (does not implement PIVParentProvider)
	mock := &mockXKMSBackend{
		generateECDSAFunc: func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
			return nil, nil
		},
		signerFunc: func(_ *types.KeyAttributes) (crypto.Signer, error) {
			return signer, nil
		},
	}

	gen := newBackendPIVKeyGenerator(mock, types.StoreSoftware)
	result, err := gen.GeneratePIVKey(pivcert.PIVSlotAuthentication, "ecdsap256", "piv-9a")
	require.NoError(t, err)
	assert.Equal(t, signer, result)

	// Verify parent is nil when backend does not implement PIVParentProvider
	require.Len(t, mock.generateCalls, 1)
	assert.Nil(t, mock.generateCalls[0].Parent)
}

func TestBackendPIVKeyGenerator_GenerateError(t *testing.T) {
	genErr := errors.New("backend generate failed")

	mock := &mockXKMSBackend{
		generateECDSAFunc: func(_ *types.KeyAttributes) (crypto.PrivateKey, error) {
			return nil, genErr
		},
	}

	gen := newBackendPIVKeyGenerator(mock, types.StoreSoftware)
	result, err := gen.GeneratePIVKey(pivcert.PIVSlotAuthentication, "ecdsap256", "piv-9a")
	assert.Nil(t, result)
	require.Error(t, err)
	assert.ErrorIs(t, err, genErr)
}

func TestBackendPIVKeyGenerator_SignerError(t *testing.T) {
	signerErr := errors.New("signer retrieval failed")

	mock := &mockXKMSBackend{
		generateECDSAFunc: func(_ *types.KeyAttributes) (crypto.PrivateKey, error) {
			return nil, nil
		},
		signerFunc: func(_ *types.KeyAttributes) (crypto.Signer, error) {
			return nil, signerErr
		},
	}

	gen := newBackendPIVKeyGenerator(mock, types.StoreSoftware)
	result, err := gen.GeneratePIVKey(pivcert.PIVSlotAuthentication, "ecdsap256", "piv-9a")
	assert.Nil(t, result)
	require.Error(t, err)
	assert.ErrorIs(t, err, signerErr)
}

// TestBackendPIVKeyGenerator_RSAGenerateError verifies that an error from
// GenerateRSA is propagated correctly through the RSA code path.
func TestBackendPIVKeyGenerator_RSAGenerateError(t *testing.T) {
	rsaErr := errors.New("rsa key generation failed")

	mock := &mockXKMSBackend{
		generateRSAFunc: func(_ *types.KeyAttributes) (crypto.PrivateKey, error) {
			return nil, rsaErr
		},
	}

	gen := newBackendPIVKeyGenerator(mock, types.StoreSoftware)
	result, err := gen.GeneratePIVKey(pivcert.PIVSlotAuthentication, "rsa2048", "piv-9a")
	assert.Nil(t, result)
	require.Error(t, err)
	assert.ErrorIs(t, err, rsaErr)
}

// TestBackendPIVKeyGenerator_Ed25519GenerateError verifies that an error from
// GenerateEd25519 is propagated correctly through the Ed25519 code path.
func TestBackendPIVKeyGenerator_Ed25519GenerateError(t *testing.T) {
	ed25519Err := errors.New("ed25519 key generation failed")

	mock := &mockXKMSBackend{
		generateEd25519Func: func(_ *types.KeyAttributes) (crypto.PrivateKey, error) {
			return nil, ed25519Err
		},
	}

	gen := newBackendPIVKeyGenerator(mock, types.StoreSoftware)
	result, err := gen.GeneratePIVKey(pivcert.PIVSlotAuthentication, "ed25519", "piv-9a")
	assert.Nil(t, result)
	require.Error(t, err)
	assert.ErrorIs(t, err, ed25519Err)
}

// TestBackendPIVKeyGenerator_PIVParentProviderError verifies that errors from
// PIVParentAttributes are propagated when the backend implements PIVParentProvider.
func TestBackendPIVKeyGenerator_PIVParentProviderError(t *testing.T) {
	parentErr := errors.New("parent attributes unavailable")

	mock := &mockXKMSBackendWithParent{
		mockXKMSBackend: mockXKMSBackend{
			generateECDSAFunc: func(_ *types.KeyAttributes) (crypto.PrivateKey, error) {
				return nil, nil
			},
		},
		parentAttrsErr: parentErr,
	}

	gen := newBackendPIVKeyGenerator(mock, types.StoreSoftware)
	result, err := gen.GeneratePIVKey(pivcert.PIVSlotAuthentication, "ecdsap256", "piv-9a")
	assert.Nil(t, result)
	require.Error(t, err)
	assert.ErrorIs(t, err, parentErr)
}

// TestBackendPIVKeyGenerator_PIVParentProviderNilAttrs verifies that when
// PIVParentAttributes returns nil attributes (no error), the parent field
// is not set on the generated key attributes.
func TestBackendPIVKeyGenerator_PIVParentProviderNilAttrs(t *testing.T) {
	signer := newTestECDSASigner(t)

	mock := &mockXKMSBackendWithParent{
		mockXKMSBackend: mockXKMSBackend{
			generateECDSAFunc: func(_ *types.KeyAttributes) (crypto.PrivateKey, error) {
				return nil, nil
			},
			signerFunc: func(_ *types.KeyAttributes) (crypto.Signer, error) {
				return signer, nil
			},
		},
		parentAttrs: nil, // nil attrs, no error
	}

	gen := newBackendPIVKeyGenerator(mock, types.StoreSoftware)
	result, err := gen.GeneratePIVKey(pivcert.PIVSlotAuthentication, "ecdsap256", "piv-9a")
	require.NoError(t, err)
	assert.Equal(t, signer, result)

	// Parent should remain nil when provider returns nil attrs
	require.Len(t, mock.generateCalls, 1)
	assert.Nil(t, mock.generateCalls[0].Parent)
}

// TestBackendPIVKeyGenerator_GetSignerError verifies that errors from the
// backend's Signer method are propagated through GetPIVSigner.
func TestBackendPIVKeyGenerator_GetSignerError(t *testing.T) {
	signerErr := errors.New("signer not available")

	mock := &mockXKMSBackend{
		signerFunc: func(_ *types.KeyAttributes) (crypto.Signer, error) {
			return nil, signerErr
		},
	}

	gen := newBackendPIVKeyGenerator(mock, types.StoreSoftware)
	result, err := gen.GetPIVSigner(pivcert.PIVSlotAuthentication, "piv-9a")
	assert.Nil(t, result)
	require.Error(t, err)
	assert.ErrorIs(t, err, signerErr)
}

// TestBackendPIVKeyGenerator_SetsPIVSlot verifies that GeneratePIVKey
// populates attrs.PIVSlot with the string representation of the slot.
// This is critical for PKCS#11 backends where resolveKeyID uses PIVSlotToCKAID
// instead of falling through to createKeyID (which causes CKR_ATTRIBUTE_VALUE_INVALID).
func TestBackendPIVKeyGenerator_SetsPIVSlot(t *testing.T) {
	signer := newTestECDSASigner(t)

	mock := &mockXKMSBackend{
		generateECDSAFunc: func(_ *types.KeyAttributes) (crypto.PrivateKey, error) {
			return nil, nil
		},
		signerFunc: func(_ *types.KeyAttributes) (crypto.Signer, error) {
			return signer, nil
		},
	}

	gen := newBackendPIVKeyGenerator(mock, types.StoreSoftware)
	result, err := gen.GeneratePIVKey(pivcert.PIVSlot("9d"), "ecdsap256", "Test CN")
	require.NoError(t, err)
	assert.Equal(t, signer, result)

	require.Len(t, mock.generateCalls, 1)
	assert.Equal(t, "9d", mock.generateCalls[0].PIVSlot,
		"PIVSlot must be set so resolveKeyID routes to PIVSlotToCKAID")
}

// TestBackendPIVKeyGenerator_SetsPIVSlotForRSA verifies that GeneratePIVKey
// populates attrs.PIVSlot for the RSA code path as well.
func TestBackendPIVKeyGenerator_SetsPIVSlotForRSA(t *testing.T) {
	signer := newTestECDSASigner(t)

	mock := &mockXKMSBackend{
		generateRSAFunc: func(_ *types.KeyAttributes) (crypto.PrivateKey, error) {
			return nil, nil
		},
		signerFunc: func(_ *types.KeyAttributes) (crypto.Signer, error) {
			return signer, nil
		},
	}

	gen := newBackendPIVKeyGenerator(mock, types.StoreSoftware)
	result, err := gen.GeneratePIVKey(pivcert.PIVSlot("9a"), "rsa2048", "RSA Test")
	require.NoError(t, err)
	assert.Equal(t, signer, result)

	require.Len(t, mock.generateCalls, 1)
	assert.Equal(t, "9a", mock.generateCalls[0].PIVSlot,
		"PIVSlot must be set so resolveKeyID routes to PIVSlotToCKAID")
}

// TestBackendPIVKeyGenerator_UnsupportedKeyAlgorithm verifies the defensive
// default branch in the key algorithm switch statement. This guards against
// a new algorithm being added to pivAlgorithmDispatch without a corresponding
// backend generation case.
func TestBackendPIVKeyGenerator_UnsupportedKeyAlgorithm(t *testing.T) {
	// Temporarily add a test entry to pivAlgorithmDispatch that returns
	// an unsupported PublicKeyAlgorithm value. This exercises the default
	// branch in the switch on attrs.KeyAlgorithm.
	const testAlgo = "test-unsupported-algo"
	pivAlgorithmDispatch[testAlgo] = func(cn string) *types.KeyAttributes {
		return &types.KeyAttributes{
			CN:           cn,
			KeyAlgorithm: x509.PublicKeyAlgorithm(99), // unsupported algorithm
			KeyType:      types.KeyTypeSigning,
		}
	}
	t.Cleanup(func() {
		delete(pivAlgorithmDispatch, testAlgo)
	})

	mock := &mockXKMSBackend{}
	gen := newBackendPIVKeyGenerator(mock, types.StoreSoftware)
	result, err := gen.GeneratePIVKey(pivcert.PIVSlotAuthentication, testAlgo, "piv-9a")
	assert.Nil(t, result)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPIVInvalidAlgorithm)
	assert.Empty(t, mock.generateCalls, "no backend generate method should have been called")
}

// TestBackendPIVKeyGenerator_GetPIVSigner_SetsPIVSlot is a regression test
// for the bug where YubiKey PIV CSR generation and public-key export failed
// with "no key found". Before the fix, GetPIVSigner built attrs with only
// CN populated. The PKCS#11 backend's resolveKeyID prefers PIVSlot over CN
// when set, so keys were unlocatable on YubiKey devices where the user-chosen
// subject CN does not match the "piv-<slot>" software convention.
func TestBackendPIVKeyGenerator_GetPIVSigner_SetsPIVSlot(t *testing.T) {
	signer := newTestECDSASigner(t)

	var captured *types.KeyAttributes
	mock := &mockXKMSBackend{
		signerFunc: func(attrs *types.KeyAttributes) (crypto.Signer, error) {
			cp := *attrs
			captured = &cp
			return signer, nil
		},
	}

	gen := newBackendPIVKeyGenerator(mock, types.StoreSoftware)
	result, err := gen.GetPIVSigner(pivcert.PIVSlotAuthentication, "any-user-chosen-cn")
	require.NoError(t, err)
	assert.Equal(t, signer, result)

	require.NotNil(t, captured, "Signer must have been invoked")
	assert.Equal(t, "9a", captured.PIVSlot,
		"PIVSlot must be set so slot-constrained backends (e.g. YubiKey PKCS#11) locate the key by CKA_ID")
	assert.Equal(t, "any-user-chosen-cn", captured.CN,
		"CN must pass through unchanged for software backends that still key off CN")
}

// TestBackendPIVKeyGenerator_GetPIVSigner_AllSlots covers every primary PIV
// slot so no slot can regress back to CN-only routing.
func TestBackendPIVKeyGenerator_GetPIVSigner_AllSlots(t *testing.T) {
	slots := []pivcert.PIVSlot{
		pivcert.PIVSlotAuthentication,
		pivcert.PIVSlotDigitalSignature,
		pivcert.PIVSlotKeyManagement,
		pivcert.PIVSlotCardAuthentication,
	}
	for _, slot := range slots {
		t.Run(string(slot), func(t *testing.T) {
			signer := newTestECDSASigner(t)
			var captured *types.KeyAttributes
			mock := &mockXKMSBackend{
				signerFunc: func(attrs *types.KeyAttributes) (crypto.Signer, error) {
					cp := *attrs
					captured = &cp
					return signer, nil
				},
			}

			gen := newBackendPIVKeyGenerator(mock, types.StoreSoftware)
			_, err := gen.GetPIVSigner(slot, "piv-"+string(slot))
			require.NoError(t, err)
			require.NotNil(t, captured)
			assert.Equal(t, string(slot), captured.PIVSlot,
				"attrs.PIVSlot must match the requested slot identifier")
		})
	}
}

// TestBackendPIVKeyGenerator_GetPIVSigner_PropagatesError verifies that a
// backend Signer error propagates unchanged out of GetPIVSigner so callers
// can inspect the original error via errors.Is.
func TestBackendPIVKeyGenerator_GetPIVSigner_PropagatesError(t *testing.T) {
	sentinel := errors.New("backend: key not found by PIVSlot")

	mock := &mockXKMSBackend{
		signerFunc: func(_ *types.KeyAttributes) (crypto.Signer, error) {
			return nil, sentinel
		},
	}

	gen := newBackendPIVKeyGenerator(mock, types.StoreSoftware)
	result, err := gen.GetPIVSigner(pivcert.PIVSlotDigitalSignature, "some-cn")
	assert.Nil(t, result)
	require.Error(t, err)
	assert.ErrorIs(t, err, sentinel,
		"errors from backend.Signer must propagate so PKCS#11 CKR_* codes reach the caller")
}
