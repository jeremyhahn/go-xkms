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

package grpc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ===========================================================================
// A key provider carrying every capability the delegated RPCs depend on.
//
// These tests exist to prove the gRPC handlers still reach a real backend
// after they were changed to delegate through the xkms service layer. Only a
// provider that implements the capability interfaces can distinguish "the RPC
// reached the backend" from "the RPC short-circuited".
// ===========================================================================

type capableProvider struct {
	keys map[string]*types.KeyAttributes

	// wrappingKey is a stable RSA key returned by GetKey and Decrypter.
	// C_WrapKey/C_UnwrapKey resolve the caller's designated wrapping key
	// through those seams and perform real RSA-OAEP, so a provider that
	// minted a fresh ECDSA key per call could neither satisfy the algorithm
	// nor round-trip: the key that wrapped would not be the key that
	// unwrapped. Created on first use so existing fixtures need no change.
	wrappingKey *rsa.PrivateKey

	exportedMaterial []byte
	exportErr        error
	unwrapped        []byte
	imported         map[string]*backend.WrappedKeyMaterial

	attestation interface{}
	attestErr   error
	attestNonce []byte

	derivedKey []byte
	deriveErr  error
	kdfParams  *types.KDFParams
}

func newCapableProvider() *capableProvider {
	return &capableProvider{
		keys:             make(map[string]*types.KeyAttributes),
		imported:         make(map[string]*backend.WrappedKeyMaterial),
		exportedMaterial: []byte("raw-symmetric-key-material-32b!!"),
		unwrapped:        []byte("recovered-key-material"),
		derivedKey:       []byte("ecdh-derived-key"),
	}
}

func (p *capableProvider) addKey(attrs *types.KeyAttributes) { p.keys[attrs.CN] = attrs }

func (p *capableProvider) Type() types.BackendType { return "capable" }

func (p *capableProvider) Capabilities() types.Capabilities {
	return types.Capabilities{Keys: true, Import: true, Export: true}
}

func (p *capableProvider) GenerateKey(_ context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	p.keys[attrs.CN] = attrs
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func (p *capableProvider) GetKey(_ context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if _, ok := p.keys[attrs.CN]; !ok {
		return nil, errors.New("key not found")
	}
	return p.rsaWrappingKey()
}

// rsaWrappingKey lazily creates and returns the provider's stable RSA key.
func (p *capableProvider) rsaWrappingKey() (*rsa.PrivateKey, error) {
	if p.wrappingKey == nil {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		p.wrappingKey = key
	}
	return p.wrappingKey, nil
}

func (p *capableProvider) DeleteKey(_ context.Context, attrs *types.KeyAttributes) error {
	delete(p.keys, attrs.CN)
	return nil
}

func (p *capableProvider) ListKeys(_ context.Context) ([]*types.KeyAttributes, error) {
	attrs := make([]*types.KeyAttributes, 0, len(p.keys))
	for _, a := range p.keys {
		attrs = append(attrs, a)
	}
	return attrs, nil
}

func (p *capableProvider) Signer(_ context.Context, _ *types.KeyAttributes) (crypto.Signer, error) {
	return nil, errors.New("not supported")
}

func (p *capableProvider) Decrypter(_ context.Context, _ *types.KeyAttributes) (crypto.Decrypter, error) {
	return p.rsaWrappingKey()
}

func (p *capableProvider) RotateKey(_ context.Context, _ *types.KeyAttributes) error { return nil }

func (p *capableProvider) Close() error { return nil }

// backend.ImportExportBackend

func (p *capableProvider) GetImportParameters(_ context.Context, _ *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
	return &backend.ImportParameters{Algorithm: algorithm, ImportToken: []byte("token")}, nil
}

func (p *capableProvider) WrapKey(_ context.Context, keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	return &backend.WrappedKeyMaterial{
		WrappedKey: append([]byte("wrapped:"), keyMaterial...),
		Algorithm:  params.Algorithm,
	}, nil
}

func (p *capableProvider) UnwrapKey(_ context.Context, _ *backend.WrappedKeyMaterial, _ *backend.ImportParameters) ([]byte, error) {
	return p.unwrapped, nil
}

func (p *capableProvider) ImportKey(_ context.Context, attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
	p.imported[attrs.CN] = wrapped
	return nil
}

func (p *capableProvider) ExportKey(_ context.Context, _ *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
	return &backend.WrappedKeyMaterial{WrappedKey: []byte("exported"), Algorithm: algorithm}, nil
}

// ExportKeyMaterial returns a COPY of the fixture's material, never the field
// itself.
//
// The service wipes the slice it receives with secure.Wipe once it has finished
// wrapping, which is correct: every production backend either returns a
// defensive copy or refuses the call outright. A double that hands back its own
// field therefore has its fixture zeroed mid-test, and the assertions below then
// compare the result against sixteen zero bytes.
func (p *capableProvider) ExportKeyMaterial(_ context.Context, _ *types.KeyAttributes) ([]byte, error) {
	if p.exportErr != nil {
		return nil, p.exportErr
	}

	material := make([]byte, len(p.exportedMaterial))
	copy(material, p.exportedMaterial)

	return material, nil
}

// types.AttestingKeyProvider

func (p *capableProvider) AttestKey(_ context.Context, _ *types.KeyAttributes, nonce []byte) (interface{}, error) {
	p.attestNonce = nonce
	if p.attestErr != nil {
		return nil, p.attestErr
	}
	return p.attestation, nil
}

// types.KeyAgreementProvider

func (p *capableProvider) DeriveKeyECDH(_ context.Context, _ *types.KeyAttributes, _ []byte, params *types.KDFParams) ([]byte, error) {
	p.kdfParams = params
	if p.deriveErr != nil {
		return nil, p.deriveErr
	}
	return p.derivedKey, nil
}

func (p *capableProvider) SupportedCurves() []string { return []string{"P-256"} }

var (
	_ backend.ImportExportBackend = (*capableProvider)(nil)
	_ types.AttestingKeyProvider  = (*capableProvider)(nil)
	_ types.KeyAgreementProvider  = (*capableProvider)(nil)
)

// setupCapableService registers the capable provider as the "hardware" backend
// alongside the capability-free "software" default.
func setupCapableService(t *testing.T) (*Service, *capableProvider) {
	t.Helper()
	xkms.Reset()
	t.Cleanup(xkms.Reset)

	provider := newCapableProvider()
	hardware, err := xkms.New(&xkms.BackendConfig{Backend: provider, CertStorage: storage.New()})
	require.NoError(t, err)

	software, err := xkms.New(&xkms.BackendConfig{Backend: newBareProvider(), CertStorage: storage.New()})
	require.NoError(t, err)

	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"hardware": hardware, "software": software},
		DefaultBackend: "software",
	}))

	svc, err := xkms.Get()
	require.NoError(t, err)
	return NewService(nil, nil, svc), provider
}

// bareProvider carries no hardware capability at all. It backs the "software"
// backend so the existing tests that expect a capability boundary keep
// exercising a genuinely incapable provider.
type bareProvider struct {
	keys map[string]*types.KeyAttributes
}

func newBareProvider() types.KeyProvider {
	return &bareProvider{keys: make(map[string]*types.KeyAttributes)}
}

func (p *bareProvider) Type() types.BackendType          { return "bare" }
func (p *bareProvider) Capabilities() types.Capabilities { return types.Capabilities{Keys: true} }
func (p *bareProvider) GenerateKey(_ context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	p.keys[attrs.CN] = attrs
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
func (p *bareProvider) GetKey(_ context.Context, _ *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, errors.New("key not found")
}
func (p *bareProvider) DeleteKey(_ context.Context, _ *types.KeyAttributes) error { return nil }
func (p *bareProvider) ListKeys(_ context.Context) ([]*types.KeyAttributes, error) {
	attrs := make([]*types.KeyAttributes, 0, len(p.keys))
	for _, a := range p.keys {
		attrs = append(attrs, a)
	}
	return attrs, nil
}
func (p *bareProvider) Signer(_ context.Context, _ *types.KeyAttributes) (crypto.Signer, error) {
	return nil, errors.New("not supported")
}
func (p *bareProvider) Decrypter(_ context.Context, _ *types.KeyAttributes) (crypto.Decrypter, error) {
	return nil, errors.New("not supported")
}
func (p *bareProvider) RotateKey(_ context.Context, _ *types.KeyAttributes) error { return nil }
func (p *bareProvider) Close() error                                              { return nil }

func capableTestCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: "attesting-key"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// ===========================================================================
// End-to-end delegation: gRPC handler -> xkms service layer -> backend
// ===========================================================================

func TestGRPCAttestKey_DelegatesToServiceLayer(t *testing.T) {
	svc, provider := setupCapableService(t)
	cert := capableTestCert(t)
	provider.attestation = &attestation.AttestationStatement{
		Format:             "tpm2",
		CertificateChain:   []*x509.Certificate{cert},
		AttestationData:    []byte("TPM2_Certify"),
		Signature:          []byte("sig"),
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Nonce:              []byte("challenge"),
		Backend:            "tpm2",
	}
	provider.addKey(&types.KeyAttributes{CN: "idevid", KeyAlgorithm: x509.ECDSA})

	resp, err := svc.AttestKey(context.Background(), &pb.AttestKeyRequest{
		Backend: "hardware",
		KeyId:   "idevid",
		Nonce:   []byte("challenge"),
	})
	require.NoError(t, err)
	assert.Equal(t, "tpm2", resp.Format)
	assert.Equal(t, "tpm2", resp.Backend)
	assert.Equal(t, []byte("TPM2_Certify"), resp.AttestationData)
	assert.Equal(t, []byte("sig"), resp.Signature)
	assert.Equal(t, x509.ECDSAWithSHA256.String(), resp.SignatureAlgorithm)
	require.Len(t, resp.CertificateChain, 1)
	assert.Equal(t, cert.Raw, resp.CertificateChain[0])
	assert.Equal(t, []byte("challenge"), provider.attestNonce)
}

func TestGRPCAttestKey_BackendFailureIsInternal(t *testing.T) {
	svc, provider := setupCapableService(t)
	provider.attestErr = errors.New("TPM_RC_POLICY_FAIL")
	provider.addKey(&types.KeyAttributes{CN: "idevid"})

	_, err := svc.AttestKey(context.Background(), &pb.AttestKeyRequest{
		Backend: "hardware", KeyId: "idevid",
	})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestGRPCDeriveKeyECDH_DelegatesToServiceLayer(t *testing.T) {
	svc, provider := setupCapableService(t)
	provider.addKey(&types.KeyAttributes{CN: "ecdh-key", KeyAlgorithm: x509.ECDSA})

	resp, err := svc.DeriveKeyECDH(context.Background(), &pb.DeriveKeyECDHRequest{
		KeyId:         "ecdh-key",
		Backend:       "hardware",
		PeerPublicKey: []byte("peer"),
		KdfAlgorithm:  "SP800-56A",
		KdfHash:       "SHA512",
		KeyLength:     48,
	})
	require.NoError(t, err)
	assert.Equal(t, []byte("ecdh-derived-key"), resp.DerivedKey)

	require.NotNil(t, provider.kdfParams)
	assert.Equal(t, types.KDFAlgorithmSP80056A, provider.kdfParams.Algorithm)
	assert.Equal(t, "SHA-512", provider.kdfParams.Hash)
	assert.Equal(t, 48, provider.kdfParams.KeyLength)
}

func TestGRPCDeriveKeyECDH_NonECDSAKeyIsInvalidArgument(t *testing.T) {
	svc, provider := setupCapableService(t)
	provider.addKey(&types.KeyAttributes{CN: "rsa-key", KeyAlgorithm: x509.RSA})

	_, err := svc.DeriveKeyECDH(context.Background(), &pb.DeriveKeyECDHRequest{
		KeyId: "rsa-key", Backend: "hardware", PeerPublicKey: []byte("peer"),
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "key must be an ECDSA key for ECDH")
}

func TestGRPCExportKeyMaterial_DelegatesToServiceLayer(t *testing.T) {
	svc, provider := setupCapableService(t)
	provider.addKey(&types.KeyAttributes{
		CN:                 "aes-key",
		KeyType:            types.KeyTypeSecret,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	})

	resp, err := svc.ExportKeyMaterial(context.Background(), &pb.ExportKeyMaterialRequest{
		KeyId:   "aes-key",
		Backend: "hardware",
	})
	require.NoError(t, err)
	assert.Equal(t, provider.exportedMaterial, resp.KeyMaterial)
	assert.Equal(t, string(types.SymmetricAES256GCM), resp.KeyType)
	assert.NotZero(t, resp.KeySize)
}

func TestGRPCExportKeyMaterial_NonExportableKeyIsFailedPrecondition(t *testing.T) {
	svc, provider := setupCapableService(t)
	provider.exportErr = errors.New("CKA_EXTRACTABLE is false")
	provider.addKey(&types.KeyAttributes{CN: "aes-key", SymmetricAlgorithm: types.SymmetricAES256GCM})

	_, err := svc.ExportKeyMaterial(context.Background(), &pb.ExportKeyMaterialRequest{
		KeyId: "aes-key", Backend: "hardware",
	})
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

func TestGRPCWrapKeyByID_DelegatesToServiceLayer(t *testing.T) {
	svc, provider := setupCapableService(t)
	provider.addKey(&types.KeyAttributes{CN: "target-key", Exportable: true})
	provider.addKey(&types.KeyAttributes{CN: "kek"})

	resp, err := svc.WrapKeyByID(context.Background(), &pb.WrapKeyByIDRequest{
		WrappingKeyId:      "kek",
		WrappingKeyBackend: "hardware",
		TargetKeyId:        "target-key",
		TargetKeyBackend:   "hardware",
		Algorithm:          "RSAES_OAEP_SHA_256",
	})
	require.NoError(t, err)
	// A real RSA-OAEP wrap, not a canned fixture prefix. The old assertion
	// expected the import ceremony's marker, which passed even though the
	// ceremony wraps under a freshly generated ephemeral key rather than the
	// caller's designated one -- the very defect C_WrapKey exists to avoid.
	assert.Len(t, resp.WrappedKey, 256, "RSA-2048 OAEP output is one modulus block")
	assert.NotEqual(t, provider.exportedMaterial, resp.WrappedKey)
	assert.Equal(t, "RSAES_OAEP_SHA_256", resp.Algorithm)

	wrappingKey, keyErr := provider.rsaWrappingKey()
	require.NoError(t, keyErr)
	recovered, decErr := wrappingKey.Decrypt(rand.Reader, resp.WrappedKey, &rsa.OAEPOptions{Hash: crypto.SHA256})
	require.NoError(t, decErr, "the blob must decrypt under the designated wrapping key")
	assert.Equal(t, provider.exportedMaterial, recovered)
}

func TestGRPCUnwrapKeyByID_DelegatesToServiceLayer(t *testing.T) {
	svc, provider := setupCapableService(t)
	provider.addKey(&types.KeyAttributes{CN: "kek"})

	// A genuine RSA-OAEP blob under the designated unwrapping key. The literal
	// "wrapped-blob" only worked while the service routed through the import
	// ceremony and never actually decrypted -- an unwrap test that could not
	// fail on a broken unwrap.
	wrappingKey, keyErr := provider.rsaWrappingKey()
	require.NoError(t, keyErr)
	realBlob, wrapErr := rsa.EncryptOAEP(crypto.SHA256.New(), rand.Reader,
		&wrappingKey.PublicKey, []byte("unwrapped-key-material"), nil)
	require.NoError(t, wrapErr)

	resp, err := svc.UnwrapKeyByID(context.Background(), &pb.UnwrapKeyByIDRequest{
		WrappedKey:           realBlob,
		UnwrappingKeyId:      "kek",
		UnwrappingKeyBackend: "hardware",
		Algorithm:            "RSAES_OAEP_SHA_256",
		TargetKeyId:          "imported-key",
		TargetKeyBackend:     "hardware",
		TargetKeyType:        "symmetric",
		TargetKeySize:        256,
	})
	require.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, "imported-key", resp.KeyId)
	assert.Equal(t, "hardware", resp.Backend)

	imported, ok := provider.imported["imported-key"]
	require.True(t, ok, "the unwrapped key must be imported into the target backend")
	// "wrapped:" is the fake importer's own marker; the suffix is what the
	// blob genuinely decrypted to, which is what proves a real unwrap rather
	// than a pass-through of canned fixture bytes.
	assert.Equal(t, append([]byte("wrapped:"), []byte("unwrapped-key-material")...), imported.WrappedKey)
}

func TestGRPCUnwrapKeyByID_UnsupportedTargetKeyTypeIsInvalidArgument(t *testing.T) {
	svc, provider := setupCapableService(t)
	provider.addKey(&types.KeyAttributes{CN: "kek"})

	// A real blob, so the request reaches the target-key-type validation this
	// test is about. With fabricated bytes it failed at decryption instead and
	// asserted nothing about key types.
	wrappingKey, keyErr := provider.rsaWrappingKey()
	require.NoError(t, keyErr)
	realBlob, wrapErr := rsa.EncryptOAEP(crypto.SHA256.New(), rand.Reader,
		&wrappingKey.PublicKey, []byte("unwrapped-key-material"), nil)
	require.NoError(t, wrapErr)

	_, err := svc.UnwrapKeyByID(context.Background(), &pb.UnwrapKeyByIDRequest{
		WrappedKey:           realBlob,
		UnwrappingKeyId:      "kek",
		UnwrappingKeyBackend: "hardware",
		Algorithm:            "RSAES_OAEP_SHA_256",
		TargetKeyId:          "imported-key",
		TargetKeyBackend:     "hardware",
		TargetKeyType:        "kyber",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "unsupported target key type")
}

// ===========================================================================
// Error mapping
// ===========================================================================

func TestMapKeyOpError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode codes.Code
		wantMsg  string
	}{
		{
			name:     "validation reports the field verbatim",
			err:      &xkms.ErrValidation{Sentinel: xkms.ErrMissingRequiredField, Detail: "key_id is required"},
			wantCode: codes.InvalidArgument,
			wantMsg:  "key_id is required",
		},
		{
			name:     "validation without detail falls back to the sentinel",
			err:      &xkms.ErrValidation{Sentinel: xkms.ErrMissingRequiredField},
			wantCode: codes.InvalidArgument,
			wantMsg:  xkms.ErrMissingRequiredField.Error(),
		},
		{
			name:     "role lookup keeps the participant name",
			err:      &xkms.ErrRoleLookup{Role: "target key backend", Name: "hsm", Err: xkms.ErrBackendNotFound},
			wantCode: codes.NotFound,
			wantMsg:  "target key backend not found",
		},
		{
			name:     "unsupported capability",
			err:      &xkms.ErrBackendUnsupported{Sentinel: xkms.ErrOperationNotSupported, Backend: "software", Detail: "does not support attestation"},
			wantCode: codes.Unimplemented,
			wantMsg:  "does not support attestation",
		},
		{
			name:     "non-exportable key",
			err:      &xkms.ErrOperationWrap{Sentinel: xkms.ErrExportKeyMaterialFailed, Err: errors.New("not extractable")},
			wantCode: codes.FailedPrecondition,
			wantMsg:  "not extractable",
		},
		{
			name:     "bare key not found",
			err:      xkms.ErrKeyNotFound,
			wantCode: codes.NotFound,
		},
		{
			name:     "service not initialized",
			err:      xkms.ErrNotInitialized,
			wantCode: codes.Unavailable,
		},
		{
			name:     "anything else is internal",
			err:      errors.New("disk on fire"),
			wantCode: codes.Internal,
			wantMsg:  "disk on fire",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mapped := mapKeyOpError(context.Background(), nil, tt.err)
			st, ok := status.FromError(mapped)
			require.True(t, ok)
			assert.Equal(t, tt.wantCode, st.Code())
			if tt.wantMsg != "" {
				assert.Contains(t, st.Message(), tt.wantMsg)
			}
		})
	}

	t.Run("nil stays nil", func(t *testing.T) {
		assert.NoError(t, mapKeyOpError(context.Background(), nil, nil))
	})
}
